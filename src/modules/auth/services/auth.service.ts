import { Inject, Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { User } from 'src/modules/users/entities';
import { LoginDto } from '../dtos';
import { AuthException, AuthErrorCode } from '../exceptions/auth.exception';
import { UserApplication } from 'src/modules/access/entities';
import { SessionPayload } from '../interfaces';
@Injectable()
export class AuthService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(UserApplication) private userAppRepository: Repository<UserApplication>,
  ) {}

  async authenticateUser({ login, password }: LoginDto): Promise<User> {
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

  async validateSession(sessionId: string) {
    const session = await this.cacheManager.get<SessionPayload>(`session:${sessionId}`);
    if (!session) {
      throw new UnauthorizedException('Session not found');
    }
    const user = await this.userRepository.findOneBy({ id: session.userId });

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
      message: isDeleted ? 'Logout successful' : 'Session is already logged out',
    };
  }

  async checkUserAppAccess(userId: string, applicationId: number) {
    const hasAccess = await this.userAppRepository.findOne({ where: { userId, applicationId } });
    if (!hasAccess) {
      throw new AuthException(AuthErrorCode.NOT_APPLICATION_ACCESS);
    }
  }
}
