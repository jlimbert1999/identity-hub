import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class System {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  code: string;

  @Column()
  name: string;

  @Column({ nullable: true })
  description?: string;

  @Column()
  apiBaseUrl: string;

  @Column({ nullable: true })
  createUserEndpoint?: string;

  @Column({ nullable: true })
  unlinkUserEndpoint?: string;

  @Column()
  publicKey: string;

  @Column({ default: true })
  isActive: boolean;
}
