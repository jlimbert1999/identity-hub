import {
  BadRequestException,
  NotFoundException,
  Injectable,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { ILike, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ulid } from 'ulid';

import { CreateUserDto, UpdateUserDto } from './dtos';
import { PaginationParamsDto } from '../common';
import { User } from './entities';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async findAll(paginationDto: PaginationParamsDto) {
    const { limit, offset, term } = paginationDto;
    const [users, length] = await this.userRepository.findAndCount({
      take: limit,
      skip: offset,
      select: { password: false },
      ...(term && {
        where: { fullName: ILike(`%${term}%`) },
      }),
      order: {
        createdAt: 'DESC',
      },
    });
    return { users, length };
  }

  async create(userDto: CreateUserDto) {
    await this.checkDuplicateLogin(userDto.login);

    const externalKey = `IDH-U-${ulid()}`;

    const passwordHash = await this.encryptPassword(userDto.password);

    const user = this.userRepository.create({
      login: userDto.login,
      password: passwordHash,
      fullName: userDto.fullName,
      relationKey: userDto.relationKey,
      externalKey,
    });

    return this.userRepository.save(user);
  }

  async update(id: string, userDto: UpdateUserDto) {
    const { password, ...toUpdate } = userDto;

    const userDB = await this.userRepository.findOneBy({ id });

    if (!userDB) throw new NotFoundException(`El usuario editado no existe`);

    if (userDto.login && userDto.login !== userDB.login) {
      await this.checkDuplicateLogin(userDto.login);
    }

    if (password) {
      userDB.password = await this.encryptPassword(password);
    }

    const updatedUser: Partial<User> = await this.userRepository.save({
      ...userDB,
      ...toUpdate,
    });

    delete updatedUser['password'];

    return updatedUser;
  }

  async findByExternalKey(id: string) {
    return this.userRepository.findOne({
      where: { id },
      relations: ['roles'],
    });
  }

  private async checkDuplicateLogin(login: string) {
    const exists = await this.userRepository.findOne({ where: { login } });
    if (exists) {
      throw new BadRequestException(`Duplicate login: ${login}`);
    }
  }

  private async encryptPassword(password: string) {
    return await bcrypt.hash(password, 12);
  }
}
