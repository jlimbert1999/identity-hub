import { Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';

import { SessionGuard } from 'src/modules/auth/guards/session.guard';
import { User } from 'src/modules/users/entities/user.entity';
import { GetUserRequest } from '../decorators/get-user-request.decorator';
import { AuthService } from '../services';
import type { Request, Response } from 'express';

@Controller('oauth')
export class OauthController {
  constructor(private authService: AuthService) {}

  @Get('status')
  @UseGuards(SessionGuard)
  checkAuthStatus(@GetUserRequest() user: User) {
    return { user: user };
  }

  @Post('logout')
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const sessionId = request.cookies['session_id'] as string | undefined;
    if (sessionId) {
      await this.authService.removeSession(sessionId);
    }

    response.clearCookie('session_id', {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });
    return { ok: true, message: 'Logout successful' };
  }
}
