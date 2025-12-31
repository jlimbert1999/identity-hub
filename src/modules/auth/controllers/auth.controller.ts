import { Get, Res, Post, Body, Query, Controller } from '@nestjs/common';

import { SSOAuthService } from '../services/oauth.service';
import {
  AuthDto,
  AuthorizeParamsDto,
  LoginParamsDto,
  RefreshTokenDto,
  TokenRequestDto,
} from '../dtos';
import type { Response } from 'express';

import { AuthException } from '../exceptions/auth.exception';
import { Cookies } from '../decorators';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: SSOAuthService) {}

  @Get('authorize')
  async authorize(
    @Query() query: AuthorizeParamsDto,
    @Cookies('session_id') sessionId: string | undefined,
    @Res() res: Response,
  ) {
    const url = await this.authService.handleAuthorize(query, sessionId);
    return res.redirect(url);
  }

  @Post('login')
  async login(
    @Body() body: AuthDto,
    @Query() queryParams: LoginParamsDto,
    @Res() res: Response,
  ) {
    try {
      const user = await this.authService.login(body);

      const sessionId = await this.authService.createSession(user);

      res.cookie('session_id', sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
      });

      const redirectUrl = await this.authService.resolveLoginSuccessRedirect(
        user,
        queryParams,
      );

      return res.redirect(redirectUrl);
    } catch (error: unknown) {
      if (error instanceof AuthException) {
        const redirectUrl = this.authService.resolveLoginErrorRedirect(
          error,
          queryParams,
        );
        return res.redirect(redirectUrl);
      }
      throw error;
    }
  }

  @Post('token')
  token(@Body() body: TokenRequestDto) {
    return this.authService.exchangeAuthorizationCode(body);
  }

  @Post('refresh')
  refresh(@Body() body: RefreshTokenDto) {
    return this.authService.refreshToken(body);
  }
}
