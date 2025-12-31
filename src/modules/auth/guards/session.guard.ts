import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';

import { AuthService } from '../services';

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request>();

    const sessionId = req.cookies['session_id'] as string | undefined;
    if (!sessionId) {
      throw new UnauthorizedException('Invalid session id');
    }
    const user = await this.authService.validateSession(sessionId);

    req['user'] = user;

    return true;
  }
}
