import { randomBytes } from 'node:crypto';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as argon2 from 'argon2';
import type { Repository } from 'typeorm';
import { RevokedToken } from '../database/entities/revoked-token.entity.js';
import { User } from '../database/entities/user.entity.js';
import type { Status } from '../database/entities/status.js';
import type { AuthUser } from './auth-user.js';
import { TokenService } from './token.service.js';

export interface LoginResult {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
}

export interface Profile {
  id: string;
  username: string;
  email: string;
  status: Status;
  roles: string[];
}

/** Mismo mensaje para usuario inexistente, inactivo o contraseña incorrecta (§4). */
const INVALID = 'Credenciales inválidas';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('Auth');
  /**
   * Hash argon2id de un valor aleatorio: si el usuario no existe se verifica contra él,
   * así el tiempo de respuesta no revela si el username existe.
   */
  private readonly dummyHash: Promise<string> = argon2.hash(
    randomBytes(32).toString('hex'),
    { type: argon2.argon2id },
  );

  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(RevokedToken)
    private readonly revoked: Repository<RevokedToken>,
    private readonly tokens: TokenService,
  ) {}

  async login(
    username: string,
    password: string,
    ip: string | undefined,
  ): Promise<LoginResult> {
    const user = await this.users
      .createQueryBuilder('u')
      .addSelect('u.passwordHash')
      .where('u.username = :username', { username })
      .getOne();

    let ok = false;
    try {
      ok = await argon2.verify(
        user?.passwordHash ?? (await this.dummyHash),
        password,
      );
    } catch {
      ok = false; // hash corrupto: se trata igual que una contraseña incorrecta
    }

    if (!user || !ok || user.status !== 'active') {
      // Nunca se registra el username ni la contraseña enviados: solo el id si existe.
      this.logger.warn(
        `login_failure user_id=${user?.id ?? '-'} ip=${ip ?? '-'}`,
      );
      throw new UnauthorizedException(INVALID);
    }

    const { token, expiresIn } = await this.tokens.sign(user.id);
    this.logger.log(`login_success user_id=${user.id} ip=${ip ?? '-'}`);
    return { access_token: token, token_type: 'Bearer', expires_in: expiresIn };
  }

  /**
   * Revoca el jti del token actual hasta su `exp` (§4). Idempotente: ON CONFLICT DO NOTHING.
   * Se registra el jti, nunca el JWT.
   */
  async logout(user: AuthUser): Promise<void> {
    await this.revoked
      .createQueryBuilder()
      .insert()
      .values({
        jti: user.jti,
        userId: user.id,
        expiresAt: new Date(user.exp * 1000),
      })
      .orIgnore()
      .execute();
    this.logger.log(`token_revoked user_id=${user.id} jti=${user.jti}`);
  }

  /** Roles vigentes leídos de la BD (solo roles activos). */
  async profile(userId: string): Promise<Profile> {
    const user = await this.users.findOneByOrFail({ id: userId });
    const rows: { name: string }[] = await this.users.query(
      `SELECT r.name FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id = $1 AND r.status = 'active'
       ORDER BY r.name`,
      [userId],
    );
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      status: user.status,
      roles: rows.map((r) => r.name),
    };
  }
}
