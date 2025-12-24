import { Controller, Get, UseGuards } from '@nestjs/common';

import { SessionGuard } from 'src/modules/access/guards/session/session.guard';
import { User } from 'src/modules/users/entities/user.entity';
import { GetUserRequest } from '../decorators/get-user-request.decorator';
import { AuthService } from '../services';

@Controller('oauth')
export class OauthController {
  constructor(private authService: AuthService) {}

  @Get('status')
  @UseGuards(SessionGuard)
  checkAuthStatus(@GetUserRequest() user: User) {
    return this.authService.getUserAuthData(user);
  }
}
