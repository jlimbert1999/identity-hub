import {
  Res,
  Req,
  Post,
  Body,
  Get,
  Query,
  Controller,
  UnauthorizedException,
} from '@nestjs/common';

import { SSOAuthService } from '../services/oauth.service';
import { AuthDto, LoginParamsDto, RefreshTokenDto } from '../dtos';
import type { Request, Response } from 'express';

import { AuthException } from '../exceptions/auth.exception';

interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  state: string;
}
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: SSOAuthService) {}

  @Get('authorize')
  async authorize2(
    @Query() query: AuthorizeParams,
    @Res() res: Response,
    @Req() req: Request,
  ) {
    const { client_id, redirect_uri, response_type, state } = query;

    // 1. Validar el tipo de respuesta
    if (response_type !== 'code') {
      return res.status(400).send('Invalid response_type');
    }

    // 2. Validar el cliente
    const client = await this.authService.validateClientRedirect(
      client_id,
      redirect_uri,
    );

    if (!client) {
      return res.status(400).send('Invalid client');
    }

    // 3. Verificar sesión SSO (IdentityHub cookie)
    const sessionId = req.cookies['session_id'] as string | undefined;

    if (!sessionId) {
      const oauthLoginId = crypto.randomUUID();

      await this.authService.saveOAuthRequest(oauthLoginId, {
        client_id,
        redirect_uri,
        state,
      });

      return res.redirect(`/login?&auth_request_id=${oauthLoginId}`);
    }

    // si ya hay sesión → OAuth directo
    const userId = (await this.authService.getSessionUser(sessionId)) as string;

    const code = await this.authService.generateAuthorizationCode({
      userId,
      clientId: client_id,
      redirectUri: redirect_uri,
    });

    // 5. Redirigir al callback del SP
    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);

    return res.redirect(url.toString());
  }

  @Post('login')
  async login(
    @Body() body: AuthDto,
    @Query() queryParams: LoginParamsDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const user = await this.authService.login(body);

      const sessionId = await this.authService.createSession(user);

      response.cookie('session_id', sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
      });

      const redirectUrl = await this.authService.resolveLoginSuccessRedirect(
        user,
        queryParams,
      );

      return response.redirect(redirectUrl);
    } catch (error: unknown) {
      if (error instanceof AuthException) {
        const redirectUrl = this.authService.resolveLoginErrorRedirect(
          error,
          queryParams,
        );
        return response.redirect(redirectUrl);
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
