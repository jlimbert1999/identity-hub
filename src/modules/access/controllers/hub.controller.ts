import { Body, Controller, Get } from '@nestjs/common';

import { GetAuthUser } from 'src/modules/auth/decorators/get-user-request.decorator';
import { User } from 'src/modules/users/entities';
import { HubService } from '../services';

@Controller('hub')
export class HubController {
  constructor(private hubService: HubService) {}

  @Get('access')
  getMyAcccess(@GetAuthUser() user: User) {
    return this.hubService.getUserApplications(user.id);
  }

  // @Get('/me/applications')
  // listApps(@Req() req) {}

  // @Get('/sso/redirect')
  // redirectToApp(@Req() req) {}
}
