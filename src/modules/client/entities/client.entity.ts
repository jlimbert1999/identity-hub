import {
  Column,
  Entity,
  OneToMany,
  CreateDateColumn,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { UserAssignment } from './user-assignment.entity';

@Entity('clients')
export class Client {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  clientKey: string;

  @Column({ length: 150 })
  name: string;

  @Column({ nullable: true })
  description?: string;

  @Column({ length: 255, nullable: true })
  baseUrl: string | null;

  @Column()
  defaultRole: string;

  @Column({ default: true })
  isActive: boolean;

  @OneToMany(() => UserAssignment, (assignment) => assignment.client)
  assignments: UserAssignment[];

  @CreateDateColumn()
  createdAt: Date;
}
