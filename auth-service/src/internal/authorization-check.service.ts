import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type { Repository } from 'typeorm';
import { AuthorizationService } from '../auth/authorization.service.js';
import { TokenService } from '../auth/token.service.js';
import { RevokedToken } from '../database/entities/revoked-token.entity.js';
import { User } from '../database/entities/user.entity.js';

export type CheckReason =
  | 'active_role_grants_permission'
  | 'no_active_role_grants_permission'
  | 'user_inactive'
  | 'token_revoked'
  | 'invalid_subject_token'
  | 'unknown_action';

/** Forma de respuesta de §11. */
export interface CheckResult {
  subject_id: string | null;
  action: string;
  allowed: boolean;
  reason: CheckReason;
  can_read_any: boolean;
}

const ANALYZE = 'steganography.analyze';
const RESULTS_READ = 'steganography.results.read';

/**
 * Decisión de autorización para STEGO (§6). Revalida el JWT como JwtAuthGuard
 * (firma/claims → jti no revocado → usuario activo) y resuelve el permiso con
 * AuthorizationService.can, la misma fuente que PermissionsGuard. La propiedad
 * del recurso la aplica STEGO con `can_read_any`; `resource_id` no se usa aquí.
 */
@Injectable()
export class AuthorizationCheckService {
  private readonly logger = new Logger('Authz');

  constructor(
    private readonly tokens: TokenService,
    private readonly authz: AuthorizationService,
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(RevokedToken)
    private readonly revoked: Repository<RevokedToken>,
  ) {}

  async check(subjectToken: string, action: string): Promise<CheckResult> {
    const result = await this.decide(subjectToken, action);
    const line = `subject_id=${result.subject_id ?? '-'} action=${action} allowed=${result.allowed} reason=${result.reason}`;
    if (result.allowed) this.logger.log(`authz_check ${line}`);
    else this.logger.warn(`authz_denied ${line}`);
    return result;
  }

  private async decide(token: string, action: string): Promise<CheckResult> {
    const deny = (subject: string | null, reason: CheckReason) => ({
      subject_id: subject,
      action,
      allowed: false,
      reason,
      can_read_any: false,
    });

    let claims;
    try {
      claims = await this.tokens.verify(token);
    } catch {
      return deny(null, 'invalid_subject_token');
    }
    const { sub, jti } = claims;

    const user = await this.users.findOne({
      where: { id: sub },
      select: { id: true, status: true },
    });
    if (!user) return deny(null, 'invalid_subject_token');
    if (await this.revoked.existsBy({ jti })) return deny(sub, 'token_revoked');
    if (user.status !== 'active') return deny(sub, 'user_inactive');

    let allowed: boolean;
    let canReadAny = false;
    if (action === ANALYZE) {
      allowed = await this.authz.can(sub, ANALYZE);
    } else if (action === RESULTS_READ) {
      canReadAny = await this.authz.can(sub, `${RESULTS_READ}_any`);
      allowed =
        canReadAny || (await this.authz.can(sub, `${RESULTS_READ}_own`));
    } else {
      return deny(sub, 'unknown_action');
    }

    return {
      subject_id: sub,
      action,
      allowed,
      reason: allowed
        ? 'active_role_grants_permission'
        : 'no_active_role_grants_permission',
      can_read_any: canReadAny,
    };
  }
}
