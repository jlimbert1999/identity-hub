import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { Application, UserApplication } from './entities';
import { AccessService, ApplicationService } from './services';
import { AccessController, ClientController, HubController } from './controllers';
import { UsersModule } from '../users/users.module';
import { HubService } from './services/hub.service';

@Module({
  controllers: [AccessController, ClientController, HubController],
  providers: [ApplicationService, AccessService, HubService],
  imports: [UsersModule, TypeOrmModule.forFeature([Application, UserApplication])],
  exports: [TypeOrmModule],
})
export class AccessModule {}
