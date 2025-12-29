import {
  Res,
  Post,
  Body,
  Get,
  Query,
  UseGuards,
  Controller,
  UnauthorizedException,
  Req,
} from '@nestjs/common';

import { SSOAuthService } from './services/oauth.service';
import { AuthDto, RefreshTokenDto } from './dtos';
import type { Request, Response } from 'express';
import { SessionGuard } from './guards/session.guard';
import { GetUserRequest } from './decorators/get-user-request.decorator';
import { User } from '../users/entities';

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

      await this.authService.savePendingOAuthRequest(oauthLoginId, {
        client_id,
        redirect_uri,
        state,
      });

      return res.redirect(`/login?context=oauth&loginId=${oauthLoginId}`);
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
    @Req() request: Request,
    @Query('context') context: 'oauth' | undefined,
    @Query('loginId') loginId: string | undefined,
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = await this.authService.login(body);

    const sessionId = await this.authService.createSession(user);

    response.cookie('session_id', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    });

    // ✅ LOGIN NORMAL (identity-hub)
    if (context !== 'oauth' || !loginId) {
      return response.redirect('http://localhost:4200/apps');
    }

    // ✅ LOGIN OAUTH
    const oauthRequest = await this.authService.getPendingOAuthRequest(loginId);

    if (!oauthRequest) {
      return response.redirect('http://localhost:4200/apps');
    }

    const { client_id, redirect_uri, state } = oauthRequest;

    const code = await this.authService.generateAuthorizationCode({
      userId: user.id,
      clientId: client_id,
      redirectUri: redirect_uri,
    });

    await this.authService.clearPendingOAuthRequest(loginId);

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);

    return response.redirect(url.toString());
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

  // @Get('status')
  // @UseGuards(AuthGuard)
  // checkAuthStatus(@Req() req: Request) {
  //   console.log(req);
  //   return {
  //     ok: true,
  //     user: req['user'],
  //   };
  // }
}
