import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import type { Status } from './status.js';

@Entity({ name: 'users' })
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 50, unique: true })
  username: string;

  @Column({ type: 'varchar', length: 254, unique: true })
  email: string;

  /** argon2id. `select: false`: nunca sale de la BD salvo que se pida explícitamente. */
  @Column({ name: 'password_hash', type: 'text', select: false })
  passwordHash: string;

  @Column({ type: 'varchar', length: 16, default: 'active' })
  status: Status;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
