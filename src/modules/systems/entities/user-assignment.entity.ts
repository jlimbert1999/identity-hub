import {
  Entity,
  Unique,
  Index,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryGeneratedColumn,
} from 'typeorm';

import { User } from 'src/modules/users/entities/user.entity';
import { System } from './system.entity';

@Entity('user_assignments')
@Unique(['user', 'system'])
export class UserAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.assignments, { eager: true })
  @Index()
  user: User;

  @ManyToOne(() => System, (system) => system.assignments, { eager: true })
  @Index()
  system: System;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
