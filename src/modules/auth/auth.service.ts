import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
// import * as bcrypt from 'bcrypt';

import { AuthDto } from './dtos/auth.dto';
import { User } from '../users/entities/user.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async login({ login, password }: AuthDto) {
    const userDB = await this.userRepository.findOneBy({ login });
    if (!userDB) {
      throw new BadRequestException('Usuario o Contraseña incorrectos');
    }

    // if (!bcrypt.compareSync(password, userDB.password)) {
    //   throw new BadRequestException('Usuario o Contraseña incorrectos');
    // }
    // if (!userDB.isActive) {
    //   throw new BadRequestException('El usuario ha sido deshabilitado');
    // }
    return true;
  }
}
