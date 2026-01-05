import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import { JwtService } from '@nestjs/jwt';

import Redis from 'ioredis';

import { AccessTokenPayload } from '../interfaces';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/modules/users/entities';
import { Repository } from 'typeorm';

@Injectable()
export class TokenService {
  private readonly ACCESS_TTL = 60 * 15; // 15 minutos
  private readonly REFRESH_TTL = 60 * 60 * 24 * 7; // 7 días

  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRedis() private readonly redis: Redis,
    private jwtService: JwtService,
  ) {}

  async generateTokenPair(accessPayload: AccessTokenPayload) {
    const refreshToken = `rt_${crypto.randomUUID()}`;

    const accessToken = await this.jwtService.signAsync(accessPayload, {
      expiresIn: this.ACCESS_TTL,
    });

    await this.redis.set(
      `refresh:${refreshToken}`,
      JSON.stringify({
        userId: accessPayload.sub,
        clientId: accessPayload.clientId,
        scope: accessPayload.scope,
      }),
      'EX',
      this.REFRESH_TTL,
    );

    await this.redis.sadd(`user_refresh_tokens:${accessPayload.sub}`, refreshToken);

    return {
      accessToken,
      refreshToken,
      token_type: 'Bearer',
      expires_in: this.ACCESS_TTL,
    };
  }

  async rotateRefreshToken(refreshToken: string, clientId: string) {
    const key = `refresh:${refreshToken}`;
    const stored = await this.redis.get(key);

    if (!stored) {
      throw new UnauthorizedException('invalid_refresh_token');
    }

    const parsed = JSON.parse(stored) as { userId: string; clientId: string; scope: string };

    if (parsed.clientId !== clientId) {
      throw new UnauthorizedException('invalid client');
    }

    // TODO ver si es necesario
    const user = await this.userRepository.findOne({
      where: { id: parsed.userId, isActive: true },
      select: ['id'], // Solo pedimos el ID para que la consulta sea ultra rápida
    });
    if (!user) {
      // 3. Si el usuario no existe o está inactivo, limpiamos TODO en Redis
      await this.revokeAllForUser(parsed.userId);
      throw new UnauthorizedException('User not authorized.');
    }

    await this.redis.del(key);
    await this.redis.srem(`user_refresh_tokens:${parsed.userId}`, refreshToken);

    return this.generateTokenPair({
      sub: parsed.userId,
      clientId: parsed.clientId,
      scope: parsed.scope,
      externalKey: user.externalKey,
      name: user.fullName,
    });
  }

  async revokeAllForUser(userId: string) {
    const setKey = `user_refresh_tokens:${userId}`;
    const tokens = await this.redis.smembers(setKey);

    if (tokens.length === 0) return;

    const pipeline = this.redis.pipeline();

    for (const token of tokens) {
      pipeline.del(`refresh:${token}`);
    }

    pipeline.del(setKey);
    await pipeline.exec();
  }
}
