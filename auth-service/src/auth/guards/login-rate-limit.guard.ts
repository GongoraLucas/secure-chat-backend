import {
  type CanActivate,
  type ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Optional,
} from '@nestjs/common';
import type { Request } from 'express';

export const LOGIN_RATE_LIMIT_OPTIONS = Symbol('LOGIN_RATE_LIMIT_OPTIONS');

export interface RateLimitOptions {
  limit: number;
  windowMs: number;
  now: () => number;
}

/**
 * Rate limit del login (§4) por IP, ventana fija y en memoria (un único proceso AUTH).
 * Sustituye a @nestjs/throttler: su build CommonJS no carga @nestjs/common 12 (solo ESM) bajo Jest.
 * 10 intentos/min: frena la fuerza bruta y deja pasar los 6 logins de la colección Postman.
 */
@Injectable()
export class LoginRateLimitGuard implements CanActivate {
  private readonly opts: RateLimitOptions;
  private readonly hits = new Map<string, { count: number; resetAt: number }>();

  constructor(
    @Optional()
    @Inject(LOGIN_RATE_LIMIT_OPTIONS)
    opts?: Partial<RateLimitOptions>,
  ) {
    this.opts = { limit: 10, windowMs: 60_000, now: Date.now, ...opts };
  }

  canActivate(ctx: ExecutionContext): boolean {
    const ip = ctx.switchToHttp().getRequest<Request>().ip ?? 'unknown';
    const now = this.opts.now();
    this.prune(now);

    const entry = this.hits.get(ip);
    if (!entry || now >= entry.resetAt) {
      this.hits.set(ip, { count: 1, resetAt: now + this.opts.windowMs });
      return true;
    }
    entry.count += 1;
    if (entry.count > this.opts.limit) {
      throw new HttpException(
        'Demasiados intentos, espera un minuto',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    return true;
  }

  /** Evita que el mapa crezca sin límite con IPs que ya no vuelven. */
  private prune(now: number): void {
    if (this.hits.size < 1000) return;
    for (const [ip, e] of this.hits) if (now >= e.resetAt) this.hits.delete(ip);
  }
}
