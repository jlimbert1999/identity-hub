import {
  Entity,
  Unique,
  Index,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryGeneratedColumn,
  Column,
} from 'typeorm';

import { User } from 'src/modules/users/entities/user.entity';
import { Client } from './client.entity';

@Entity('user_assignments')
@Unique(['user', 'client'])
export class UserAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.assignments, { eager: true })
  @Index()
  user: User;

  @ManyToOne(() => Client, (system) => system.assignments, { eager: true })
  @Index()
  client: Client;

  @Column({ nullable: true })
  userId: string;

  @Column({ nullable: true })
  clientId: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
