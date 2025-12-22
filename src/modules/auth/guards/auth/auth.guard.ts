import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { UsersService } from 'src/modules/users/users.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = request.cookies['identity_access'] as string | undefined;

    if (!token) throw new UnauthorizedException('No token provided');

    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(token);
    } catch {
      console.log('error valdacion toekn');
      throw new UnauthorizedException();
    }

    const user = await this.usersService.findByExternalKey(payload.externalKey);

    if (!user || !user.isActive) {
      throw new UnauthorizedException();
    }

    request['user'] = {
      id: user.id,
      fullName: user.fullName,
      roles: user.roles,
    };

    return true;
  }
}
