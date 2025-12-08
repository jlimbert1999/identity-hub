import { Post, Body, Controller, Res } from '@nestjs/common';

import { AuthService } from './auth.service';
import {
  AuthorizeDtoGrouped,
  DirectLoginDto,
  ExchangeCodeDto,
  RefreshTokenDto,
} from './dtos';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('direct-login')
  directLogin(@Body() dto: DirectLoginDto) {
    return this.authService.directLogin(dto);
  }

  @Post('authorize')
  async authorize(
    @Body() body: AuthorizeDtoGrouped,
    @Res() response: Response,
  ) {
    const { redirectUri, state } = body;
    const user = await this.authService.validateUser(body);
    const code = await this.authService.generateAuthCode(
      user.id,
      body.clientId,
    );

    const url = new URL(redirectUri);
    url.searchParams.set('code', code);
    if (state) {
      url.searchParams.set('state', state);
    }

    return response.redirect(url.toString());
  }

  @Post('exchange')
  async exchange(@Body() body: ExchangeCodeDto) {
    return this.authService.exchangeCode(body);
  }

  @Post('refresh')
  refresh(@Body() body: RefreshTokenDto) {
    return this.authService.refreshToken(body);
  }
}
