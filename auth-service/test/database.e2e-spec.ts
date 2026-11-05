import * as argon2 from 'argon2';
import { DataSource } from 'typeorm';
import { validateEnv } from '../src/config/env.schema.js';
import { buildDataSourceOptions } from '../src/database/typeorm-options.js';
import { User } from '../src/database/entities/user.entity.js';
import { runSeed } from '../src/database/seeds/seed.js';

/**
 * A2 · Esquema de identidad contra Postgres real (../scripts/test-db.sh up).
 * Evidencia de §3 (tablas, N:M, UNIQUE en BD) y §5 (matriz cargada por seed).
 */

// Matriz §5 transcrita aquí a propósito: el test comprueba que el seed la refleja.
const MATRIX: Record<string, string[]> = {
  ADMIN: [
    'profile.read',
    'users.manage',
    'roles.manage',
    'user_roles.manage',
    'steganography.analyze',
    'steganography.results.read_own',
    'steganography.results.read_any',
  ],
  ANALYST: [
    'profile.read',
    'steganography.analyze',
    'steganography.results.read_own',
  ],
  USER: ['profile.read'],
};

const env = validateEnv(process.env);
let ds: DataSource;

async function count(sql: string, params: unknown[] = []): Promise<number> {
  const rows: { n: string }[] = await ds.query(sql, params);
  return Number(rows[0].n);
}

async function insertUser(username: string): Promise<string> {
  const rows: { id: string }[] = await ds.query(
    `INSERT INTO users (username, email, password_hash)
     VALUES ($1, $2, 'x') RETURNING id`,
    [username, `${username}@example.com`],
  );
  return rows[0].id;
}

async function insertRole(name: string): Promise<string> {
  const rows: { id: string }[] = await ds.query(
    `INSERT INTO roles (name, description) VALUES ($1, 'test') RETURNING id`,
    [name],
  );
  return rows[0].id;
}

async function assign(userId: string, roleId: string): Promise<void> {
  await ds.query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [
    userId,
    roleId,
  ]);
}

beforeAll(async () => {
  ds = new DataSource(buildDataSourceOptions(env));
  await ds.initialize();
  await ds.dropDatabase();
  await ds.runMigrations();
});

afterAll(async () => {
  await ds?.destroy();
});

describe('migración InitIdentitySchema', () => {
  it('crea las 6 tablas y no usa synchronize', async () => {
    expect(ds.options.synchronize).toBe(false);
    const rows: { table_name: string }[] = await ds.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name <> 'migrations'`,
    );
    expect(rows.map((r) => r.table_name).sort()).toEqual(
      [
        'permissions',
        'revoked_tokens',
        'role_permissions',
        'roles',
        'user_roles',
        'users',
      ].sort(),
    );
  });

  it('T06: UNIQUE(user_id, role_id) definido en BD rechaza duplicados (23505)', async () => {
    const u = await insertUser('dup_user');
    const r = await insertRole('DUP_ROLE');
    await assign(u, r);
    await expect(assign(u, r)).rejects.toMatchObject({
      driverError: { code: '23505' },
    });
  });

  it('T05: N:M — un usuario con 2 roles y un rol con 2 usuarios', async () => {
    const ana = await insertUser('nm_ana');
    const beto = await insertUser('nm_beto');
    const analyst = await insertRole('NM_ANALYST');
    const user = await insertRole('NM_USER');
    await assign(ana, analyst);
    await assign(ana, user);
    await assign(beto, analyst);

    expect(
      await count(`SELECT count(*) n FROM user_roles WHERE user_id = $1`, [
        ana,
      ]),
    ).toBe(2);
    expect(
      await count(`SELECT count(*) n FROM user_roles WHERE role_id = $1`, [
        analyst,
      ]),
    ).toBe(2);
  });

  it('borrar un usuario borra sus asignaciones (ON DELETE CASCADE)', async () => {
    const u = await insertUser('cascade_user');
    const r = await insertRole('CASCADE_ROLE');
    await assign(u, r);
    await ds.query(`DELETE FROM users WHERE id = $1`, [u]);
    expect(
      await count(`SELECT count(*) n FROM user_roles WHERE user_id = $1`, [u]),
    ).toBe(0);
  });

  it('una asignación a un usuario inexistente es rechazada por la FK (23503)', async () => {
    const r = await insertRole('FK_ROLE');
    await expect(
      assign('00000000-0000-0000-0000-000000000000', r),
    ).rejects.toMatchObject({ driverError: { code: '23503' } });
  });

  it('status fuera de active|inactive es rechazado por CHECK (23514)', async () => {
    await expect(
      ds.query(
        `INSERT INTO users (username, email, password_hash, status)
         VALUES ('bad_status', 'bad@example.com', 'x', 'banned')`,
      ),
    ).rejects.toMatchObject({ driverError: { code: '23514' } });
  });
});

describe('seed', () => {
  beforeAll(async () => {
    await runSeed(ds, env);
  });

  it('crea los roles ADMIN, ANALYST y USER activos', async () => {
    const rows: { name: string; status: string }[] = await ds.query(
      `SELECT name, status FROM roles WHERE name IN ('ADMIN','ANALYST','USER')
       ORDER BY name`,
    );
    expect(rows).toEqual([
      { name: 'ADMIN', status: 'active' },
      { name: 'ANALYST', status: 'active' },
      { name: 'USER', status: 'active' },
    ]);
  });

  it('los permisos de cada rol coinciden exactamente con la matriz §5', async () => {
    for (const [role, perms] of Object.entries(MATRIX)) {
      const rows: { name: string }[] = await ds.query(
        `SELECT p.name FROM role_permissions rp
         JOIN roles r ON r.id = rp.role_id
         JOIN permissions p ON p.id = rp.permission_id
         WHERE r.name = $1`,
        [role],
      );
      expect(rows.map((x) => x.name).sort()).toEqual([...perms].sort());
    }
  });

  it('crea el admin desde env con hash argon2id y rol ADMIN', async () => {
    const rows: { password_hash: string; status: string; email: string }[] =
      await ds.query(
        `SELECT password_hash, status, email FROM users WHERE username = $1`,
        [env.ADMIN_USERNAME],
      );
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('active');
    expect(rows[0].email).toBe(env.ADMIN_EMAIL);
    expect(rows[0].password_hash.startsWith('$argon2id$')).toBe(true);
    expect(await argon2.verify(rows[0].password_hash, env.ADMIN_PASSWORD)).toBe(
      true,
    );
    expect(
      await count(
        `SELECT count(*) n FROM user_roles ur
         JOIN users u ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id
         WHERE u.username = $1 AND r.name = 'ADMIN'`,
        [env.ADMIN_USERNAME],
      ),
    ).toBe(1);
  });

  it('es idempotente: ejecutarlo de nuevo no duplica nada ni cambia el hash', async () => {
    const snapshot = async () => ({
      roles: await count(`SELECT count(*) n FROM roles`),
      permissions: await count(`SELECT count(*) n FROM permissions`),
      rolePermissions: await count(`SELECT count(*) n FROM role_permissions`),
      users: await count(`SELECT count(*) n FROM users`),
      userRoles: await count(`SELECT count(*) n FROM user_roles`),
      hash: (
        (await ds.query(`SELECT password_hash FROM users WHERE username = $1`, [
          env.ADMIN_USERNAME,
        ])) as { password_hash: string }[]
      )[0].password_hash,
    });
    const before = await snapshot();
    await runSeed(ds, env);
    expect(await snapshot()).toEqual(before);
  });

  it('el repositorio de User no devuelve password_hash por defecto', async () => {
    const admin = await ds
      .getRepository(User)
      .findOneByOrFail({ username: env.ADMIN_USERNAME });
    expect(admin.username).toBe(env.ADMIN_USERNAME);
    // select:false → el hash no se carga ni aparece al serializar.
    expect(admin.passwordHash).toBeUndefined();
    expect(JSON.stringify(admin)).not.toMatch(/argon2|password/i);
  });
});
