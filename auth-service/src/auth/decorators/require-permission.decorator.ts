import { Reflector } from '@nestjs/core';

/**
 * Permiso que exige una ruta protegida por PermissionsGuard, p. ej. `@RequirePermission('users.manage')`.
 * Solo nombra el permiso: quién lo tiene se decide en la BD (AuthorizationService).
 */
export const RequirePermission = Reflector.createDecorator<string>();
