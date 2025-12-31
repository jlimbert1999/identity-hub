import { Get, Res, Post, Body, Query, Controller } from '@nestjs/common';
import type { Response } from 'express';

import {
  AuthDto,
  LoginParamsDto,
  RefreshTokenDto,
  TokenRequestDto,
  AuthorizeParamsDto,
} from '../dtos';

import { AuthException } from '../exceptions/auth.exception';
import { OAuthService } from '../services';
import { Cookies } from '../decorators';

@Controller('oauth')
export class OAuthController {
  constructor(private readonly oAuthService: OAuthService) {}

  @Get('authorize')
  async authorize(
    @Query() query: AuthorizeParamsDto,
    @Cookies('session_id') sessionId: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    const url = await this.oAuthService.handleAuthorize(query, sessionId);
    return res.redirect(url);
  }

  @Post('login')
  async login(
    @Body() body: AuthDto,
    @Query() queryParams: LoginParamsDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const user = await this.oAuthService.login(body);

      const sessionId = await this.oAuthService.createSession(user);

      res.cookie('session_id', sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
      });

      const redirectUrl = await this.oAuthService.resolveLoginSuccessRedirect(
        user,
        queryParams,
      );
      console.log(redirectUrl);

      return res.redirect(redirectUrl);
    } catch (error: unknown) {
      if (error instanceof AuthException) {
        const redirectUrl = this.oAuthService.resolveLoginErrorRedirect(
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
    return this.oAuthService.exchangeAuthorizationCode(body);
  }

  @Post('refresh')
  refresh(@Body() body: RefreshTokenDto) {
    return this.oAuthService.refreshToken(body);
  }
}
