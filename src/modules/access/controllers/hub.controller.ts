import { Body, Controller, Get, Req, UseGuards } from '@nestjs/common';
import { SessionGuard } from '../../auth/guards/session.guard';
import { HubService } from '../services';
import { GetUserRequest } from 'src/modules/auth/decorators/get-user-request.decorator';
import { User } from 'src/modules/users/entities';

@Controller('hubs')
export class HubController {
  constructor(private hubService: HubService) {}

  @Get('access')
  getMyAcccess(@GetUserRequest() user: User) {
    return this.hubService.getUserApplications(user.id);
  }

  // @Get('/me/applications')
  // listApps(@Req() req) {}

  // @Get('/sso/redirect')
  // redirectToApp(@Req() req) {}
}
