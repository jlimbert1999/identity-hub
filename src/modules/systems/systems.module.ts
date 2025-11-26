import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { SystemsService } from './systems.service';
import { SystemsController } from './systems.controller';
import { System } from './entities';

@Module({
  controllers: [SystemsController],
  providers: [SystemsService],
  imports: [TypeOrmModule.forFeature([System])],
})
export class SystemsModule {}
