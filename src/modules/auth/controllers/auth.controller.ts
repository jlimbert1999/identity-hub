import { Controller, Get, Post, Res, UseGuards } from '@nestjs/common';

import type { Response } from 'express';

import { SessionGuard } from 'src/modules/auth/guards/session.guard';
import { User } from 'src/modules/users/entities';

import { Cookies, GetUserRequest } from '../decorators';
import { AuthService } from '../services';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('status')
  @UseGuards(SessionGuard)
  checkAuthStatus(@GetUserRequest() user: User) {
    return { user: user };
  }

  @Post('logout')
  async logout(
    @Cookies('session_id') sessionId: string | undefined,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.authService.removeSession(sessionId);
    response.clearCookie('session_id', {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });
    return result;
  }
}
