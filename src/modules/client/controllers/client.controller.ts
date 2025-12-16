import {
  Body,
  Get,
  Post,
  Query,
  Param,
  Patch,
  Controller,
} from '@nestjs/common';

import { PaginationParamsDto } from 'src/modules/common';
import { ClientService } from '../services';
import { CreateClientDto, UpdateClientDto } from '../dtos';

@Controller('clients')
export class ClientController {
  constructor(private readonly clientService: ClientService) {}

  @Post()
  create(@Body() createClientDto: CreateClientDto) {
    return this.clientService.create(createClientDto);
  }

  @Get()
  findAll(@Query() queryParams: PaginationParamsDto) {
    return this.clientService.findAll(queryParams);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateClientDto: UpdateClientDto) {
    return this.clientService.update(+id, updateClientDto);
  }
}
