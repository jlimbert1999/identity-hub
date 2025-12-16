import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { Client, UserAssignment } from './entities';
import { AssigmentService, ClientService } from './services';
import { AssigmentController, ClientController } from './controllers';

@Module({
  controllers: [AssigmentController, ClientController],
  providers: [ClientService, AssigmentService],
  imports: [TypeOrmModule.forFeature([Client, UserAssignment])],
  exports: [TypeOrmModule],
})
export class SystemsModule {}
