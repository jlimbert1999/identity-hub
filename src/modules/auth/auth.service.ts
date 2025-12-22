import {
  Inject,
  Injectable,
  ForbiddenException,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';

import { randomBytes } from 'node:crypto';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { Client, UserAssignment } from '../client/entities';
import { AuthDto, ExchangeCodeDto, RefreshTokenDto } from './dtos/auth.dto';
import { User } from '../users/entities/user.entity';
import { RefreshTokenPayload, GenerateTokenProperties } from './interfaces';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    // @InjectRepository(Client) private clientRepository: Repository<Client>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private jwtService: JwtService,
  ) {}

  async validateUser({ login, password }: AuthDto): Promise<User> {
    const userDB = await this.userRepository.findOne({
      where: { login },
    });
    console.log(userDB);
    if (!userDB) {
      throw new BadRequestException('Usuario o contraseña incorrectos');
    }

    const isValid = bcrypt.compareSync(password, userDB.password);
    if (!isValid) {
      throw new BadRequestException('Usuario o contraseña incorrectos');
    }

    if (!userDB.isActive) {
      throw new BadRequestException('El usuario ha sido deshabilitado');
    }

    return userDB;
  }

  async exchangeCode(data: ExchangeCodeDto) {
    const { code, client_id } = data;
    console.log(code, client_id);

    const payload = await this.consumeAuthCode(code, client_id);
    // payload = { userId, clientId }

    // Recuperas el usuario
    // (podrías mover esto a AuthService si prefieres)
    console.log(payload);
    const user = await this.userRepository.findOne({
      where: { id: payload.userId },
    });
    console.log(user);

    if (!user) {
      throw new BadRequestException('Usuario no encontrado para este code');
    }

    return this.issueTokens(user, payload.clientId);
  }

  async generateAuthCode(clientId: string) {
    const code = randomBytes(32).toString('hex');

    const payload = { clientId };

    try {
      await this.cacheManager.set(`authcode:${code}`, payload, 120 * 1000);
    } catch (error) {
      console.log(error);
    }

    return code;
  }

  async consumeAuthCode(code: string, clientId: string) {
    const payload: { userId: string; clientId: string } | undefined =
      await this.cacheManager.get(`authcode:${code}`);

    if (!payload) {
      throw new BadRequestException('Authorization code inválido o expirado');
    }

    if (payload.clientId !== clientId) {
      throw new UnauthorizedException('ClientId inválido para este code');
    }

    await this.cacheManager.del(`authcode:${code}`);

    return payload;
  }

  async issueTokens(user: User, clientId: string) {
    const payloadBase = {
      sub: user.id,
      clientId,
      // si tienes globalUserId: globalUserId: user.globalId,
    };

    const accessToken = await this.jwtService.signAsync(payloadBase, {
      expiresIn: '1m',
    });

    const refreshToken = await this.jwtService.signAsync(
      { ...payloadBase, type: 'refresh' },
      {
        expiresIn: '1d',
      },
    );
    console.log('generate');
    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        login: user.login,
        // agrega lo que quieras exponer:
        // name: user.name,
        // email: user.email,
      },
    };
  }

  async refreshToken(dto: RefreshTokenDto) {
    const payload = await this.jwtService.verifyAsync<RefreshTokenPayload>(
      dto.refreshToken,
    );

    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
      relations: { assignments: true },
    });

    if (!user) throw new UnauthorizedException();

    const hasAssignment = await this.userHasClientAssignment(
      user,
      payload.clientKey,
    );
    if (!hasAssignment) throw new UnauthorizedException();

    return this.generateAuthTokens({
      sub: user.id,
      externalKey: user.externalKey,
      clientKey: payload.clientKey,
    });
  }

  async refreshApiTokens(refreshToken: string) {
    let payload: any;

    try {
      payload = await this.jwtService.verifyAsync(refreshToken);
    } catch {
      throw new UnauthorizedException();
    }

    // Solo identidad
    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
      relations: { roles: true },
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedException();
    }

    return this.generateApiTokens(user);
  }

  private async userHasClientAssignment(user: User, clientKey: string) {
    return true;
    // return user.assignments.some((user) => user === client.id);
  }

  private async generateAuthTokens(properties: GenerateTokenProperties) {
    const { sub, externalKey, clientKey } = properties;
    const accessToken = await this.jwtService.signAsync(
      { sub, externalKey, clientKey },
      { expiresIn: '1m' },
    );

    const refreshToken = await this.jwtService.signAsync(
      { sub, clientKey },
      { expiresIn: '1d' },
    );

    return { accessToken, refreshToken };
  }

  async generateApiTokens(user: User) {
    const accessToken = await this.jwtService.signAsync(
      {
        sub: user.id,
        externalKey: user.externalKey,
        type: 'identity', // opcional pero recomendable
      },
      { expiresIn: '15m' },
    );

    const refreshToken = await this.jwtService.signAsync(
      {
        sub: user.id,
        type: 'identity',
      },
      { expiresIn: '7d' },
    );

    return { accessToken, refreshToken };
  }

  // 🔹 1. Validar que client_id existe y redirect_uri es válido
  async validateClientRedirect(
    clientId: string,
    redirectUri: string,
  ): Promise<boolean> {
    // const client = await this.clientRepository.findOne({
    //   where: { clientKey: clientId },
    // });

    // if (!client) return false;

    // El redirect debe coincidir EXACTAMENTE
    // if (client.re !== redirectUri) return false;

    return true;
  }

  // 2️⃣ Obtener userId desde una sesión
  async getUserFromSession(sessionId: string) {
    return await this.cacheManager.get<string>(`session:${sessionId}`);
  }

  async savePendingOAuthRequest(data: {
    client_id: string;
    redirect_uri: string;
    state?: string;
  }) {
    // 5 minutos de vigencia
    await this.cacheManager.set('pendingOAuth', data, 300_000);
  }

  async getPendingOAuthRequest(): Promise<
    | {
        client_id: string;
        redirect_uri: string;
        state?: string;
      }
    | null
    | undefined
  > {
    return await this.cacheManager.get('pendingOAuth');
  }

  async createSession(userId: string): Promise<string> {
    const sessionId = crypto.randomUUID();

    await this.cacheManager.set(`session:${sessionId}`, userId, 24 * 60 * 60);

    return sessionId;
  }

  async getSessionUser(sessionId: string): Promise<string | null | undefined> {
    return await this.cacheManager.get(`session:${sessionId}`);
  }

  async generateAuthorizationCode(data: {
    userId: string;
    clientId: string;
    redirectUri: string;
  }) {
    const code = crypto.randomUUID();

    await this.cacheManager.set(`authcode:${code}`, data, 300);

    return code;
  }

  async consumeAuthorizationCode(code: string): Promise<{
    userId: string;
    clientId: string;
    redirectUri: string;
  } | null> {
    const key = `authcode:${code}`;
    const data = await this.cacheManager.get(key);

    if (!data) return null;

    // Evita reuso
    await this.cacheManager.del(key);
    return data as any;
  }

  async generateTokens(payload: { userId: string; clientId: string }) {
    const access_token = await this.jwtService.signAsync(
      {
        sub: payload.userId,
        client: payload.clientId,
      },
      { expiresIn: '1m' },
    );

    const refresh_token = await this.jwtService.signAsync(
      {
        sub: payload.userId,
        client: payload.clientId,
        type: 'refresh',
      },
      { expiresIn: '1d' },
    );

    return { access_token, refresh_token };
  }
}
