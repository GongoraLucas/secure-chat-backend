import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Unique,
  type Relation,
} from 'typeorm';
import { Role } from './role.entity.js';
import { User } from './user.entity.js';

/** Tabla asociativa real N:M. UNIQUE(user_id, role_id) también existe en la migración. */
@Entity({ name: 'user_roles' })
@Unique('uq_user_roles_user_role', ['userId', 'roleId'])
export class UserRole {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @Column({ name: 'role_id', type: 'uuid' })
  roleId: string;

  @CreateDateColumn({ name: 'assigned_at', type: 'timestamptz' })
  assignedAt: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: Relation<User>;

  @ManyToOne(() => Role, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'role_id' })
  role: Relation<Role>;
}
