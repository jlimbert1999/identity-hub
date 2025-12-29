import {
  Entity,
  Unique,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryGeneratedColumn,
  Column,
} from 'typeorm';

import { User } from 'src/modules/users/entities/user.entity';
import { Application } from './application.entity';

@Entity('user_applications')
@Unique(['user', 'application'])
export class UserApplication {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.accesses, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Application, (system) => system.userAccesses, {
    onDelete: 'CASCADE',
  })
  application: Application;

  @Column({ nullable: true })
  userId: string;

  @Column({ nullable: true })
  applicationId: number;

  @CreateDateColumn()
  createdAt: Date;
}
