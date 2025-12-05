import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ulid } from 'ulid';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  findAll() {
    return `This action returns all users`;
  }

  findOne(id: number) {
    return `This action returns a #${id} user`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }

  async create(dto: CreateUserDto) {
    // 1. Verificar login único
    const exists = await this.userRepository.findOne({
      where: { login: dto.login },
    });
    if (exists) {
      throw new BadRequestException('El login ya está registrado');
    }

    // 2. Generar externalKey
    const externalKey = `IDH-U-${ulid()}`;

    // 3. Generar hash de contraseña
    const passwordHash = await bcrypt.hash(dto.password, 12);

    // 4. Crear entidad
    const user = this.userRepository.create({
      fullName: dto.fullName,
      login: dto.login,
      relationKey: dto.relationKey,
      externalKey,
      password: passwordHash,
    });

    // 5. Guardar en BD
    return this.userRepository.save(user);
  }
}
