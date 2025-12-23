import {
  Post,
  Body,
  Controller,
  Res,
  Get,
  Query,
  UnauthorizedException,
  UseGuards,
  Req,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { AuthDto, RefreshTokenDto } from './dtos';
import type { Request, Response } from 'express';
import { AuthGuard } from './guards/auth/auth.guard';
import { SessionGuard } from '../access/guards/session/session.guard';

interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  state: string;
}
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('authorize')
  async authorize2(@Query() query: AuthorizeParams, @Res() res: Response) {
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
      return res.status(400).send('Invalid client_id or redirect_uri');
    }

    // 3. Verificar sesión SSO (IdentityHub cookie)
    const sessionId = res.req.cookies['session_id'] as string | undefined;

    if (!sessionId) {
      // 3a. Guardar intento OAuth en Redis para recuperarlo después del login
      await this.authService.savePendingOAuthRequest({
        client_id,
        redirect_uri,
        state,
      });

      // 3b. Redirigir al login del frontend del IdentityHub
      return res.redirect(`/login`);
    }

    // 4. Si hay sesión, generar authorization code
    const code = await this.authService.generateAuthorizationCode({
      userId: (await this.authService.getSessionUser(sessionId)) ?? '',
      clientId: client_id,
      redirectUri: redirect_uri,
    });

    // 5. Redirigir al callback del SP
    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    console.log(url.toString());
    return res.redirect(url.toString());
  }

  @Post('login')
  async login(@Body() body: AuthDto, @Res() response: Response) {
    // Validar credenciales
    const user = await this.authService.validateUser(body);
    if (!user) {
      return response.status(401).send('Invalid credentials');
    }

    // Crear sesión central
    const sessionId = await this.authService.createSession(user.id);

    // Guardar cookie HttpOnly
    response.cookie('session_id', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // true en prod
      maxAge: 24 * 60 * 60 * 1000, // 1 día
    });

    // 3. Cargar pending request
    const oauthRequest = await this.authService.getPendingOAuthRequest();
    if (!oauthRequest) {
      return response.redirect('http://localhost:4300/apps'); // fallback
    }

    const { client_id, redirect_uri, state } = oauthRequest;

    // 4. Generar authorization code
    const code = await this.authService.generateAuthorizationCode({
      userId: user.id,
      clientId: client_id,
      redirectUri: redirect_uri,
    });

    // 5. Redirigir al callback del SP
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

  @Get('status')
  @UseGuards(SessionGuard)
  status(@Req() req: Request) {
    return {
      ok: true,
      user: req['user'],
    };
  }
}
