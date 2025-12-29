import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import type { Request, Response } from 'express';
import { SSOAuthService } from '../services';

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(private readonly authService: SSOAuthService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request>();
    const res = ctx.switchToHttp().getResponse<Response>();

    const sessionId = req.cookies['session_id'] as string | undefined;
    if (!sessionId) return this.fail(req, res);
    const user = await this.authService.validateSession(sessionId);
    if (!user) return this.fail(req, res);

    req['user'] = user;

    return true;
  }

  private fail(req: Request, res: Response): boolean {
    // Si es una llamada fetch/XHR, devolvemos 401; si es navegación, redirect.
    const accept = req.headers.accept ?? '';
    const isApi =
      accept.includes('application/json') ||
      req.headers['x-requested-with'] === 'XMLHttpRequest';

    if (isApi) {
      res.status(401).json({ authenticated: false });
    } else {
      res.redirect('/login');
    }
    return false;
  }
}
