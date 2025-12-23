import { Body, Controller, Get, Post } from '@nestjs/common';
import { ApplicationService, AssigmentService } from '../services';
import { CreateAssigmentDto } from '../dtos';

@Controller('assigment')
export class AssigmentController {
  constructor(
    private assigmentService: AssigmentService,
    private applicationService: ApplicationService,
  ) {}

  @Get('applications')
  getApplications() {
    return this.applicationService.getAllActive();
  }

  @Post()
  create(@Body() body: CreateAssigmentDto) {
    return this.assigmentService.assignUser(body);
  }
}
