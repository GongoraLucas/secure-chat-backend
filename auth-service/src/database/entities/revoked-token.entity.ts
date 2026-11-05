import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
  type Relation,
} from 'typeorm';
import { User } from './user.entity.js';

/** jti revocados por logout; se consultan en cada petición autenticada (§4). */
@Entity({ name: 'revoked_tokens' })
export class RevokedToken {
  @PrimaryColumn({ type: 'uuid' })
  jti: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @CreateDateColumn({ name: 'revoked_at', type: 'timestamptz' })
  revokedAt: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: Relation<User>;
}
