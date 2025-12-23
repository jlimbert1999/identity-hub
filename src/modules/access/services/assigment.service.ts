import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';

import { User } from 'src/modules/users/entities';
import { Application, UserApplication } from '../entities';
import { CreateAssigmentDto } from '../dtos';

@Injectable()
export class AssigmentService {
  constructor(
    @InjectRepository(Application)
    private clientRepository: Repository<Application>,
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(UserApplication)
    private assigmentRespository: Repository<UserApplication>,
  ) {}

  async assignUser(assigmentDto: CreateAssigmentDto) {
    const { userId, applicationIds } = assigmentDto;
    const user = await this.userRepository.findOneBy({ id: userId });

    if (!user) throw new NotFoundException('User not fount');

    const applications = await this.clientRepository.find({
      where: { id: In(applicationIds) },
    });

    if (applications.length !== applicationIds.length) {
      const missingIds = applicationIds.filter(
        (clientId) => !applications.some(({ id }) => id === clientId),
      );
      throw new BadRequestException(
        `Missing clients: ${missingIds.join(', ')}`,
      );
    }

    const assignments = applications.map((application) =>
      this.assigmentRespository.create({
        user,
        application,
      }),
    );

    try {
      await this.assigmentRespository.save(assignments);
      return assignments;
    } catch (error: unknown) {
      console.log(error);
      throw new BadRequestException('Error creating assignments');
    }
  }
}
