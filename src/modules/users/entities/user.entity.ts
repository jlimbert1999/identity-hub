import { UserAssignment } from 'src/modules/systems/entities';
import {
  Column,
  Entity,
  OneToMany,
  UpdateDateColumn,
  CreateDateColumn,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  login: string;

  @Column()
  password: string;

  @Column()
  fullName: string;

  @Column({ nullable: true })
  externalKey?: string;

  @Column({ unique: true, nullable: true })
  email: string;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => UserAssignment, (userAssigment) => userAssigment.user, {
    cascade: true,
  })
  assignments: UserAssignment[];
}
