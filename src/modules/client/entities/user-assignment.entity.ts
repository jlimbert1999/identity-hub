import {
  Entity,
  Unique,
  Index,
  Column,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryGeneratedColumn,
} from 'typeorm';

import { User } from 'src/modules/users/entities/user.entity';
import { Application } from './application.entity';

@Entity('user_applications')
@Unique(['user', 'client'])
export class UserApplications {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.applications, { onDelete: 'CASCADE' })
  @Index()
  user: User;

  @ManyToOne(() => Application, (system) => system.applications, {
    onDelete: 'CASCADE',
  })
  @Index()
  client: Application;

  @Column({ nullable: true })
  userId: string;

  @Column({ nullable: true })
  clientId: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
