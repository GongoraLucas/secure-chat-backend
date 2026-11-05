import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import type { AuthUser } from '../auth-user.js';
import { AuthorizationService } from '../authorization.service.js';
import { RequirePermission } from '../decorators/require-permission.decorator.js';

/**
 * Va SIEMPRE después de JwtAuthGuard: `@UseGuards(JwtAuthGuard, PermissionsGuard)`.
 * Deny by default: sin `req.user` → 401; sin `@RequirePermission` o sin el permiso en BD → 403.
 * Solo usa `req.user.id` (puesto por JwtAuthGuard); nunca roles del JWT, cabeceras ni body.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger('Authz');

  constructor(
    private readonly reflector: Reflector,
    private readonly authz: AuthorizationService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request & { user?: AuthUser }>();
    const userId = req.user?.id;
    if (!userId) throw new UnauthorizedException('No autenticado');

    const permission = this.reflector.getAllAndOverride(RequirePermission, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    const route = `${req.method} ${req.originalUrl}`;
    if (!permission || !(await this.authz.can(userId, permission))) {
      this.logger.warn(
        `authz_denied user_id=${userId} permission=${permission ?? '-'} route=${route}`,
      );
      throw new ForbiddenException('Permiso denegado');
    }
    return true;
  }
}
