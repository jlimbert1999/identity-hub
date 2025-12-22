import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';

import { User } from 'src/modules/users/entities';
import { Application, UserApplications } from '../entities';
import { CreateAssigmentDto } from '../dtos';

@Injectable()
export class AssigmentService {
  constructor(
    @InjectRepository(Application)
    private clientRepository: Repository<Application>,
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(UserApplications)
    private assigmentRespository: Repository<UserApplications>,
  ) {}

  async assignUser(assigmentDto: CreateAssigmentDto) {
    const { userId, clientIds } = assigmentDto;
    const user = await this.userRepository.findOneBy({ id: userId });

    if (!user) throw new NotFoundException('User not fount');

    const clients = await this.clientRepository.find({
      where: { id: In(clientIds) },
    });

    if (clients.length !== clientIds.length) {
      const missingIds = clientIds.filter(
        (clientId) => !clients.some(({ id }) => id === clientId),
      );
      throw new BadRequestException(
        `Missing clients: ${missingIds.join(', ')}`,
      );
    }

    const assignments = clients.map((client) =>
      this.assigmentRespository.create({
        user,
        client,
      }),
    );

    await this.assigmentRespository.save(assignments);

    return assignments;
  }
}
