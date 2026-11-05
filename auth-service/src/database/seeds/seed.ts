import * as argon2 from 'argon2';
import type { DataSource } from 'typeorm';
import type { Env } from '../../config/env.schema.js';
import {
  SEED_PERMISSIONS,
  SEED_ROLE_PERMISSIONS,
  SEED_ROLES,
} from './seed-data.js';

/**
 * Seed idempotente: roles, permisos de la matriz §5 y admin inicial desde env.
 * ON CONFLICT DO NOTHING → re-ejecutarlo no duplica ni sobrescribe (tampoco el hash del admin).
 * Todo en una transacción.
 */
export async function runSeed(ds: DataSource, env: Env): Promise<void> {
  await ds.transaction(async (m) => {
    for (const r of SEED_ROLES) {
      await m.query(
        `INSERT INTO roles (name, description) VALUES ($1, $2)
         ON CONFLICT (name) DO NOTHING`,
        [r.name, r.description],
      );
    }
    for (const p of SEED_PERMISSIONS) {
      await m.query(
        `INSERT INTO permissions (name, description) VALUES ($1, $2)
         ON CONFLICT (name) DO NOTHING`,
        [p.name, p.description],
      );
    }
    for (const [role, perms] of Object.entries(SEED_ROLE_PERMISSIONS)) {
      await m.query(
        `INSERT INTO role_permissions (role_id, permission_id)
         SELECT r.id, p.id FROM roles r, permissions p
         WHERE r.name = $1 AND p.name = ANY($2::text[])
         ON CONFLICT (role_id, permission_id) DO NOTHING`,
        [role, perms],
      );
    }

    const existing: unknown[] = await m.query(
      `SELECT 1 FROM users WHERE username = $1`,
      [env.ADMIN_USERNAME],
    );
    if (existing.length === 0) {
      const hash = await argon2.hash(env.ADMIN_PASSWORD, {
        type: argon2.argon2id,
      });
      await m.query(
        `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [env.ADMIN_USERNAME, env.ADMIN_EMAIL, hash],
      );
    }
    await m.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r
       WHERE u.username = $1 AND r.name = 'ADMIN'
       ON CONFLICT (user_id, role_id) DO NOTHING`,
      [env.ADMIN_USERNAME],
    );
  });
}
