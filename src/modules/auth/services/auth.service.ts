import {
  Inject,
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { User } from 'src/modules/users/entities';
@Injectable()
export class AuthService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async validateSession(sessionId: string) {
    const userId = await this.cacheManager.get<string>(`session:${sessionId}`);
    if (!userId) {
      throw new UnauthorizedException('Session not found');
    }
    const user = await this.userRepository.findOneBy({ id: userId });

    if (!user) {
      throw new UnauthorizedException(`Invalid session`);
    }

    if (!user.isActive) {
      throw new UnauthorizedException(`User is disabled`);
    }
    return {
      id: user.id,
      fullName: user.fullName,
      roles: user.roles,
    };
  }

  async removeSession(sessionId: string | undefined) {
    if (!sessionId) throw new BadRequestException('Invalid session id');
    const isDeleted = await this.cacheManager.del(`session:${sessionId}`);
    return {
      ok: true,
      message: isDeleted
        ? 'Logout successful'
        : 'Session is already logged out',
    };
  }
}
