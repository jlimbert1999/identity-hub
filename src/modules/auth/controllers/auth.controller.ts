import {
  Get,
  Res,
  Post,
  Body,
  Query,
  Controller,
  UnauthorizedException,
  Req,
} from '@nestjs/common';

import { SSOAuthService } from '../services/oauth.service';
import {
  AuthDto,
  AuthorizeParamsDto,
  LoginParamsDto,
  RefreshTokenDto,
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
  async token(
    @Body() dto: { code: string; client_id: string; redirect_uri: string },
  ) {
    const { code, client_id, redirect_uri } = dto;
    const authCode = await this.authService.consumeAuthorizationCode(code);

    if (!authCode) {
      throw new UnauthorizedException('Invalid or expired code');
    }

    if (authCode.clientId !== client_id) {
      throw new UnauthorizedException('Invalid client');
    }

    if (authCode.redirectUri !== redirect_uri) {
      console.log(authCode.redirectUri);
      throw new UnauthorizedException('Invalid redirect_uri');
    }

    // 1. Generar tokens
    const tokens = await this.authService.generateTokens({
      userId: authCode.userId,
      clientId: authCode.clientId,
    });

    return tokens;
  }

  @Post('refresh')
  refresh(@Body() body: RefreshTokenDto) {
    return this.authService.refreshToken(body);
  }
}
