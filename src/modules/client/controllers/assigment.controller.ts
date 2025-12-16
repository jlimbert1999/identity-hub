import { Body, Controller, Post } from '@nestjs/common';
import { AssigmentService } from '../services';
import { CreateAssigmentDto } from '../dtos';

@Controller('assigment')
export class AssigmentController {
  constructor(private readonly assigmentService: AssigmentService) {}

  @Post()
  create(@Body() body: CreateAssigmentDto) {
    return this.assigmentService.assignUser(body);
  }
}
