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
@Unique(['user', 'application'])
export class UserApplication {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.applications, { onDelete: 'CASCADE' })
  @Index()
  user: User;

  @ManyToOne(() => Application, (system) => system.applications, {
    onDelete: 'CASCADE',
  })
  @Index()
  application: Application;

  @Column({ nullable: true })
  userId: string;

  @Column({ nullable: true })
  applicationId: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
