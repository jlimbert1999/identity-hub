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
    if (!user) {
      return response.status(401).send('Invalid credentials');
    }
    const { accessToken, refreshToken } =
      await this.authService.generateApiTokens(user);

    response.cookie('identity_access', accessToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    response.cookie('identity_refresh', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    return { ok: true };
  }

  // 🔄 REFRESH
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.['identity_refresh'];
    if (!refreshToken) {
      throw new UnauthorizedException();
    }

    const { accessToken, refreshToken: newRefresh } =
      await this.authService.refreshApiTokens(refreshToken);

    res.cookie('identity_access', accessToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    res.cookie('identity_refresh', newRefresh, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    return { ok: true };
  }

  // ✅ STATUS
  @Get('status')
  @UseGuards(AuthGuard)
  status(@Req() req: Request) {
    return {
      ok: true,
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
}
