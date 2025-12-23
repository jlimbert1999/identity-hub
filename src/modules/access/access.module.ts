import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { Application, UserApplication } from './entities';
import { AssigmentService, ApplicationService } from './services';
import { AssigmentController, ClientController } from './controllers';
import { UsersModule } from '../users/users.module';

@Module({
  controllers: [AssigmentController, ClientController],
  providers: [ApplicationService, AssigmentService],
  imports: [
    UsersModule,
    TypeOrmModule.forFeature([Application, UserApplication]),
  ],
})
export class AccessModule {}
