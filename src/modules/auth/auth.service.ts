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

import { Client, UserAssignment } from '../systems/entities';
import { AuthDto, ExchangeCodeDto, RefreshTokenDto } from './dtos/auth.dto';
import { User } from '../users/entities/user.entity';
import { DirectLoginDto } from './dtos';
import { RefreshTokenPayload, GenerateTokenProperties } from './interfaces';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(Client) private clientRepository: Repository<Client>,
    @InjectRepository(UserAssignment)
    private userAssignmentRepository: Repository<UserAssignment>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private jwtService: JwtService,
  ) {}

  async validateUser({ login, password }: AuthDto): Promise<User> {
    const userDB = await this.userRepository.findOne({
      where: { login },
    });

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
    const user = await this.userRepository.findOne({
      where: { id: payload.userId },
    });

    if (!user) {
      throw new BadRequestException('Usuario no encontrado para este code');
    }

    return this.issueTokens(user, payload.clientId);
  }

  async generateAuthCode(userId: string, clientId: string) {
    const code = randomBytes(32).toString('hex');

    const payload = { userId, clientId };

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
      expiresIn: '15m',
    });

    const refreshToken = await this.jwtService.signAsync(
      { ...payloadBase, type: 'refresh' },
      {
        expiresIn: '30d',
      },
    );

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

  async directLogin(loginDto: DirectLoginDto) {
    const { login, password, clientKey } = loginDto;

    const user = await this.userRepository.findOne({
      where: { login },
      relations: { assignments: true },
    });
    if (!user) {
      throw new UnauthorizedException('Incorrect username or password.');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new UnauthorizedException('Incorrect username or password.');
    }

    const isAssignment = await this.verifyAssigment(user, clientKey);

    if (isAssignment) throw new UnauthorizedException();

    const { accessToken, refreshToken } = await this.generateAuthTokens({
      sub: user.id,
      externalKey: user.externalKey,
      clientKey,
    });

    return { accessToken, refreshToken };
  }

  async refreshToken(dto: RefreshTokenDto) {
    try {
      await this.jwtService.verifyAsync(dto.refreshToken);

      const payload = this.jwtService.decode<RefreshTokenPayload>(
        dto.refreshToken,
      );

      const user = await this.userRepository.findOne({
        where: { id: payload.sub },
        relations: { assignments: true },
      });

      if (!user) throw new UnauthorizedException();

      const isAssignment = await this.verifyAssigment(user, payload.clientKey);

      if (isAssignment) throw new UnauthorizedException();

      const { accessToken, refreshToken } = await this.generateAuthTokens({
        sub: user.id,
        externalKey: user.externalKey,
        clientKey: payload.clientKey,
      });

      return {
        accessToken,
        refreshToken,
        externalKey: user.externalKey,
      };
    } catch (error: unknown) {
      console.log(error);
      throw new UnauthorizedException();
    }
  }

  private async verifyAssigment(user: User, clientKey: string) {
    const client = await this.clientRepository.findOneBy({ clientKey });

    if (!client) throw new ForbiddenException(`${clientKey} is not valid.`);

    return user.assignments.some((user) => user.clientId === client.id);
  }

  private async generateAuthTokens(properties: GenerateTokenProperties) {
    const { sub, externalKey, clientKey } = properties;
    const accessToken = await this.jwtService.signAsync(
      { sub, externalKey, clientKey },
      { expiresIn: '15m' },
    );

    const refreshToken = await this.jwtService.signAsync(
      { sub, clientKey },
      { expiresIn: '7d' },
    );

    return { accessToken, refreshToken };
  }
}
