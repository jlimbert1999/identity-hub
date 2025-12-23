import { Body, Controller, Get, Req, UseGuards } from '@nestjs/common';
import { SessionGuard } from '../../guards/session/session.guard';

@Controller('hubs')
@UseGuards(SessionGuard)
export class HubController {
  @Get('/apps')
  apps() {}

  @Get('/me/applications')
  listApps(@Req() req) {}

  @Get('/sso/redirect')
  redirectToApp(@Req() req) {}
}
