import { Get, Res, Post, Body, Query, Controller } from '@nestjs/common';
import type { Response } from 'express';

import { LoginDto, LoginParamsDto, TokenRequestDto, AuthorizeParamsDto } from '../dtos';

import { AuthException } from '../exceptions/auth.exception';
import { Cookies, Public } from '../decorators';
import { OAuthService } from '../services';

@Controller('oauth')
export class OAuthController {
  constructor(private readonly oAuthService: OAuthService) {}

  @Public()
  @Get('authorize')
  async authorize(
    @Query() query: AuthorizeParamsDto,
    @Cookies('session_id') sessionId: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    const url = await this.oAuthService.handleAuthorizeRequest(query, sessionId);
    return res.redirect(url);
  }

  @Public()
  @Post('login')
  async login(@Body() body: LoginDto, @Query() queryParams: LoginParamsDto, @Res({ passthrough: true }) res: Response) {
    try {
      const sessionId = await this.oAuthService.handleLoginRequest(body);
      res.cookie('session_id', sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
      });

      const redirectUrl = await this.oAuthService.resumeAuthorizeFlow(queryParams);
      return res.redirect(redirectUrl);
    } catch (error: unknown) {
      if (error instanceof AuthException) {
        const redirectUrl = this.oAuthService.resolveLoginErrorRedirect(error, queryParams);
        return res.redirect(redirectUrl);
      }
      throw error;
    }
  }

  @Public()
  @Post('token')
  token(@Body() body: TokenRequestDto) {
    return this.oAuthService.handleTokenRequest(body);
  }
}
