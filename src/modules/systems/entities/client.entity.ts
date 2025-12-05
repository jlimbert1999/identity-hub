import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { UserAssignment } from './user-assignment.entity';

@Entity('clients')
export class Client {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  clientKey: string;

  @Column({ type: 'varchar', length: 150 })
  name: string;

  @Column({ nullable: true })
  description?: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  baseUrl: string | null;

  @Column()
  publicKey: string;

  @OneToMany(() => UserAssignment, (assignment) => assignment.client)
  assignments: UserAssignment[];
}
