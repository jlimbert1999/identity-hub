import {
  Column,
  Entity,
  OneToMany,
  CreateDateColumn,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { UserApplication } from './user-application.entity';

@Entity('applications')
export class Application {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  clientKey: string;

  @Column({ length: 150 })
  name: string;

  @Column({ nullable: true })
  description?: string;

  @Column({ length: 255, nullable: true })
  baseUrl?: string;

  @Column({ nullable: true })
  defaultRole: string;

  @Column({ default: true })
  isActive: boolean;

  @OneToMany(() => UserApplication, (assignment) => assignment.application)
  userAccesses: UserApplication[];

  @CreateDateColumn()
  createdAt: Date;
}
