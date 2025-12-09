import {
  Post,
  Body,
  Controller,
  Res,
  Get,
  Query,
  Req,
  UnauthorizedException,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import {
  AuthDto,
  AuthorizeDto,
  AuthorizeDtoGrouped,
  DirectLoginDto,
  ExchangeCodeDto,
  RefreshTokenDto,
} from './dtos';
import type { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('direct-login')
  async directLogin(@Body() dto: DirectLoginDto, @Res() res: Response) {
    const result = await this.authService.directLogin(dto);
    res.cookie('sso_session', '1234', {
      httpOnly: true,
      secure: false, // true en producción
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      // domain: 'http://localhost:8000', // el dominio real
    });
    res.json(result);
  }

  // @Post('authorize')
  // async authorize(
  //   @Body() body: AuthorizeDtoGrouped,
  //   @Res() response: Response,
  // ) {
  //   const { redirectUri, state } = body;
  //   // const user = await this.authService.validateUser(body);
  //   const code = await this.authService.generateAuthCode(body.clientId);

  //   const url = new URL(redirectUri);
  //   url.searchParams.set('code', code);
  //   if (state) {
  //     url.searchParams.set('state', state);
  //   }

  //   return response.redirect(url.toString());
  // }

  @Get('authorize')
  async authorize(
    @Req() req: Request,
    @Res() res: Response,
    @Query() query: AuthorizeDto, // ⬅ DTO aquí
  ) {
    const { client_id, redirect_uri, response_type, scope } = query;

    // 1️⃣ Validar client_id y redirect_uri contra la DB
    const allowed = await this.authService.validateClientRedirect(
      client_id,
      redirect_uri,
    );
    if (!allowed) {
      return res.status(400).send('Invalid redirect_uri or client_id');
    }

    // 2️⃣ Verificar si hay sesión SSO
    const sessionId = req.cookies['session_id'];

    if (!sessionId) {
      const loginUrl = `/login?redirect=${encodeURIComponent(req.originalUrl)}`;
      return res.redirect(loginUrl);
    }

    // 3️⃣ Buscar usuario autenticado
    const userId = await this.authService.getUserFromSession(sessionId);
    if (!userId) {
      const loginUrl = `/login?redirect=${encodeURIComponent(req.originalUrl)}`;
      return res.redirect(loginUrl);
    }

    // 4️⃣ Usuario OK → generar authorization_code
    const code = await this.authService.generateAuthorizationCode({
      userId,
      clientId: client_id,
      redirectUri: redirect_uri,
      scope,
    });
    
    // 5️⃣ Redirigir al SP callback con el code
    const redirect = new URL(redirect_uri);
    redirect.searchParams.set('code', code);
    console.log(redirect);

    return res.redirect(redirect.toString());
  }

  @Post('exchange')
  async exchange(@Body() body: ExchangeCodeDto) {
    console.log('call excahne');
    return this.authService.exchangeCode(body);
  }

  @Post('refresh')
  refresh(@Body() body: RefreshTokenDto) {
    return this.authService.refreshToken(body);
  }

  @Post('login')
  async login(@Body() body: AuthDto, @Res() response: Response) {
    const {
      redirectUrl = 'http://localhost:8000/auth/authorize?client_id=intranet&redirect_uri=http://localhost:3000/auth/callback&response_type=code&scope=openid',
    } = body;

    // Validar credenciales
    const user = await this.authService.validateUser(body);
    if (!user) throw new UnauthorizedException('Credenciales incorrectas');

    // Crear sesión central
    const sessionId = await this.authService.createSession(user.id);

    // Guardar cookie HttpOnly
    response.cookie('session_id', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // true en prod
      maxAge: 24 * 60 * 60 * 1000, // 1 día
    });
    // Redirect no lo decide Angular, lo decide backend
    return response.redirect(redirectUrl || '/');
  }
}
