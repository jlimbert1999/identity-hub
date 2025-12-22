import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { Client, UserAssignment } from './entities';
import { AssigmentService, ClientService } from './services';
import { AssigmentController, ClientController } from './controllers';
import { UsersModule } from '../users/users.module';

@Module({
  controllers: [AssigmentController, ClientController],
  providers: [ClientService, AssigmentService],
  imports: [UsersModule, TypeOrmModule.forFeature([Client, UserAssignment])],
})
export class ClientModule {}
