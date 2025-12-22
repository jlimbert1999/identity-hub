import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '../guards/auth/auth.guard';
import type { Request, Response } from 'express';
import { LoginDto } from '../dtos/login.dto';
import { AuthService } from '../auth.service';

@Controller('oauth')
export class OauthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = await this.authService.validateUser(body);
    const result = await this.authService.generateApiTokens(user);

    response.cookie('identity_access', result.accessToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    response.cookie('identity_refresh', result.refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    return { ok: true, message: 'Login successful' };
  }

  // ✅ STATUS
  @Get('status')
  @UseGuards(AuthGuard)
  status(@Req() req: Request) {
    return {
      user: req['user'],
    };
  }

  // 🚪 LOGOUT
  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('identity_access');
    res.clearCookie('identity_refresh');
    return { ok: true };
  }

  @Post('refresh')
  async refreshInternal(@Req() req: Request, @Res() res: Response) {
    console.log('Refreshing internal token');
    const refreshToken = req.cookies['identity_refresh'] as string | undefined;
    console.log(refreshToken);
    if (!refreshToken) {
      throw new UnauthorizedException();
    }

    const tokens = await this.authService.refreshInternalToken(refreshToken);

    res.cookie('identity_access', tokens.accessToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('identity_refresh', tokens.refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.json({ ok: true });
  }
}
