import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type { Request } from 'express';
import type { Repository } from 'typeorm';
import { RevokedToken } from '../../database/entities/revoked-token.entity.js';
import { User } from '../../database/entities/user.entity.js';
import type { AuthenticatedRequest } from '../auth-user.js';
import { TokenService } from '../token.service.js';

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

/**
 * Bearer → firma/claims (TokenService) → jti no revocado → usuario existe y está activo.
 * Cualquier fallo → 401 con el mismo mensaje. Deja `req.user = {id, jti, exp}`.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly tokens: TokenService,
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(RevokedToken)
    private readonly revoked: Repository<RevokedToken>,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request>();
    const match = BEARER.exec(req.headers.authorization ?? '');
    if (!match) throw new UnauthorizedException('No autenticado');

    let claims;
    try {
      claims = await this.tokens.verify(match[1]);
    } catch {
      throw new UnauthorizedException('No autenticado');
    }
    if (await this.revoked.existsBy({ jti: claims.jti })) {
      throw new UnauthorizedException('No autenticado');
    }
    const active = await this.users.existsBy({
      id: claims.sub,
      status: 'active',
    });
    if (!active) throw new UnauthorizedException('No autenticado');

    (req as AuthenticatedRequest).user = {
      id: claims.sub,
      jti: claims.jti,
      exp: claims.exp,
    };
    return true;
  }
}
