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

import { Application, UserApplication } from '../../access/entities';
import {
  AuthDto,
  ExchangeCodeDto,
  LoginParamsDto,
  RefreshTokenDto,
} from '../dtos/auth.dto';
import { User, UserRole } from '../../users/entities/user.entity';
import {
  RefreshTokenPayload,
  GenerateTokenProperties,
  AuthAccessTokenPayload,
  PendingAuthRequest,
} from '../interfaces';
import { AuthErrorCode, AuthException } from '../exceptions/auth.exception';

@Injectable()
export class SSOAuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    // @InjectRepository(Client) private clientRepository: Repository<Client>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private jwtService: JwtService,
  ) {}

  async login({ login, password }: AuthDto): Promise<User> {
    const userDB = await this.userRepository
      .createQueryBuilder('user')
      .where('user.login = :login', { login })
      .addSelect('user.password')
      .getOne();

    if (!userDB) {
      throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

    const isValid = bcrypt.compareSync(password, userDB.password);
    if (!isValid) {
      throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

    if (!userDB.isActive) {
      throw new AuthException(AuthErrorCode.USER_DISABLED);
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
      relations: { accesses: true },
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

  async refreshInternalToken(refreshToken: string) {
    const payload =
      await this.jwtService.verifyAsync<RefreshTokenPayload>(refreshToken);

    // if (payload.clientKey !== 'identity-hub-admin') {
    //   throw new UnauthorizedException();
    // }

    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
    });

    if (!user) throw new UnauthorizedException();

    return this.generateAuthTokens({
      sub: user.id,
      externalKey: user.externalKey,
      clientKey: 'identity-hub-admin',
    });
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
    const payload: AuthAccessTokenPayload = { sub: user.id };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });

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

  async saveOAuthRequest(oAuthRequestId: string, data: PendingAuthRequest) {
    const key = `pending_oauth:${oAuthRequestId}`;
    await this.cacheManager.set(key, data, 300 * 1000);
  }

  async getOAuthRequest(oAuthRequestId: string) {
    const key = `pending_oauth:${oAuthRequestId}`;
    const data = await this.cacheManager.get<PendingAuthRequest>(key);
    return data ?? null;
  }

  async clearOAuthRequest(oauthLoginId: string): Promise<void> {
    const key = `pending_oauth:${oauthLoginId}`;
    await this.cacheManager.del(key);
  }

  async createSession(user: User) {
    const sessionId = crypto.randomUUID();
    const key = `session:${sessionId}`;
    await this.cacheManager.set(key, user.id, 24 * 60 * 60 * 1000);
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

  async validateSession(sessionId: string) {
    const userId = await this.cacheManager.get<string>(`session:${sessionId}`);
    if (!userId) return null;
    const user = await this.userRepository.findOneBy({ id: userId });

    if (!user || !user.isActive) {
      return null;
    }

    // 4️⃣ Devolver usuario “limpio”
    return {
      id: user.id,
      fullName: user.fullName,
      roles: user.roles,
    };
  }

  async resolveLoginSuccessRedirect(user: User, params: LoginParamsDto) {
    const { auth_request_id } = params;

    if (!auth_request_id) return 'http://localhost:4200/apps';

    const oauthRequest = await this.getOAuthRequest(auth_request_id);

    if (!oauthRequest) return 'http://localhost:4200/apps';

    await this.clearOAuthRequest(auth_request_id);

    const code = await this.generateAuthorizationCode({
      userId: user.id,
      clientId: oauthRequest.client_id,
      redirectUri: oauthRequest.redirect_uri,
    });

    const url = new URL(oauthRequest.redirect_uri);

    url.searchParams.set('code', code);

    if (oauthRequest.state) url.searchParams.set('state', oauthRequest.state);

    return url.toString();
  }

  resolveLoginErrorRedirect(error: AuthException, params: LoginParamsDto) {
    const { auth_request_id } = params;

    const url = new URL('http://localhost:4200/login');

    url.searchParams.set('error', error.code);

    if (auth_request_id) {
      url.searchParams.set('auth_request_id', auth_request_id);
    }

    return url.toString();
  }
}
