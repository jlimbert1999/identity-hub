import { Post, Body, Controller, Query, Res } from '@nestjs/common';

import { AuthService } from './auth.service';
import {
  AuthDto,
  AuthorizeDto,
  AuthorizeDtoGrouped,
  ExchangeCodeDto,
} from './dtos/auth.dto';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() body: AuthDto) {
    return this.authService.login(body);
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

  // "ADMIN"
  // "$2b$10$OcWwBFQoU3z2JgpsEaVysejz54h.E..WAf26yuG2U.glVndbSpjd2"
}
