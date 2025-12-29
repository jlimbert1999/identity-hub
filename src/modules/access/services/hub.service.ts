import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { UserApplication } from '../entities';

@Injectable()
export class HubService {
  constructor(
    @InjectRepository(UserApplication)
    private userAppRepository: Repository<UserApplication>,
  ) {}

  async getUserApplications(userId: string) {
    const result = await this.userAppRepository.find({
      where: { user: { id: userId } },
      relations: { application: true },
    });
    console.log(result);
    return result;
  }
}
