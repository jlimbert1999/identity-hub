import {
  Get,
  Post,
  Body,
  Patch,
  Param,
  Query,
  Controller,
} from '@nestjs/common';

import { CreateUserDto, UpdateUserDto } from './dtos';
import { UsersService } from './users.service';
import { PaginationParamsDto } from '../common';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  findAll(@Query() paginationParams: PaginationParamsDto) {
    return this.usersService.findAll(paginationParams);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }
}
