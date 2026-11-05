import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type { DataSource } from 'typeorm';
import { UUID } from './token.service.js';

/**
 * Única fuente de decisiones RBAC (§5): la usan PermissionsGuard y, en A7, el endpoint interno.
 * Concede solo si usuario activo + asignación en user_roles + rol activo + rol con el permiso.
 * Una consulta por decisión, sin caché: retirar una asignación surte efecto en la siguiente petición (T07).
 */
const CAN_SQL = `
SELECT 1
FROM users u
JOIN user_roles ur       ON ur.user_id = u.id
JOIN roles r             ON r.id = ur.role_id AND r.status = 'active'
JOIN role_permissions rp ON rp.role_id = r.id
JOIN permissions p       ON p.id = rp.permission_id
WHERE u.id = $1 AND u.status = 'active' AND p.name = $2
LIMIT 1`;

@Injectable()
export class AuthorizationService {
  constructor(@InjectDataSource() private readonly ds: DataSource) {}

  async can(userId: string, permission: string): Promise<boolean> {
    // users.id es uuid: un id que no lo sea no puede tener permisos (y evita un error de cast en Postgres).
    if (!UUID.test(userId)) return false;
    const rows = (await this.ds.query(CAN_SQL, [
      userId,
      permission,
    ])) as unknown[];
    return rows.length > 0;
  }
}
