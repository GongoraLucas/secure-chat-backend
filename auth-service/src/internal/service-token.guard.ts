import { createHash, timingSafeEqual } from 'node:crypto';
import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import type { Env } from '../config/env.schema.js';

const digest = (v: string) => createHash('sha256').update(v, 'utf8').digest();

/**
 * Autentica al servicio llamante (STEGO) por `X-Service-Token` (§6).
 * Se comparan los SHA-256 con timingSafeEqual: longitudes siempre iguales y
 * tiempo constante, sin filtrar la longitud del secreto. Nunca se registra el valor.
 */
@Injectable()
export class ServiceTokenGuard implements CanActivate {
  private readonly logger = new Logger('ServiceAuth');
  private readonly expected: Buffer;

  constructor(config: ConfigService<Env, true>) {
    this.expected = digest(config.get('SERVICE_TOKEN', { infer: true }));
  }

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const header = req.headers['x-service-token'];
    const ok =
      typeof header === 'string' &&
      header.length > 0 &&
      timingSafeEqual(digest(header), this.expected);
    if (!ok) {
      this.logger.warn(`service_auth_failed ip=${req.ip ?? '-'}`);
      throw new UnauthorizedException('Servicio no autenticado');
    }
    return true;
  }
}
