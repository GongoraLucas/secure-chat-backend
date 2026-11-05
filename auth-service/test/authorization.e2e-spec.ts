import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as argon2 from 'argon2';
import request from 'supertest';
import { App } from 'supertest/types.js';
import { DataSource } from 'typeorm';
import { AppModule } from '../src/app.module.js';
import { AuthorizationService } from '../src/auth/authorization.service.js';
import { configureApp } from '../src/common/app-setup.js';
import { validateEnv } from '../src/config/env.schema.js';
import { runSeed } from '../src/database/seeds/seed.js';
import { buildDataSourceOptions } from '../src/database/typeorm-options.js';

/**
 * A4 · RBAC resuelto en la BD en cada consulta (§5), contra Postgres real
 * (../scripts/test-db.sh up). Incluye T07 a nivel de servicio: quitar la
 * asignación deniega en la llamada siguiente, sin caché.
 */

const env = validateEnv(process.env);
const PASSWORD = 'Rbac-Test-Pass-1234';
const UNKNOWN_UUID = '00000000-0000-4000-8000-000000000000';

let ds: DataSource;
let app: INestApplication<App>;
let authz: AuthorizationService;
let hash: string;

async function createUser(username: string, roles: string[] = []) {
  const [{ id }] = (await ds.query(
    `INSERT INTO users (username, email, password_hash)
     VALUES ($1, $2, $3) RETURNING id`,
    [username, `${username}@example.com`, hash],
  )) as Array<{ id: string }>;
  for (const role of roles) await assign(id, role);
  return id;
}

async function assign(userId: string, role: string) {
  await ds.query(
    `INSERT INTO user_roles (user_id, role_id)
     SELECT $1, id FROM roles WHERE name = $2`,
    [userId, role],
  );
}

async function unassign(userId: string, role: string) {
  await ds.query(
    `DELETE FROM user_roles
     WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE name = $2)`,
    [userId, role],
  );
}

async function adminId(): Promise<string> {
  const [{ id }] = (await ds.query(`SELECT id FROM users WHERE username = $1`, [
    env.ADMIN_USERNAME,
  ])) as Array<{ id: string }>;
  return id;
}

beforeAll(async () => {
  ds = new DataSource(buildDataSourceOptions(env));
  await ds.initialize();
  await ds.dropDatabase();
  await ds.runMigrations();
  await runSeed(ds, env);
  hash = await argon2.hash(PASSWORD, { type: argon2.argon2id });

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();
  app = moduleRef.createNestApplication<INestApplication<App>>();
  configureApp(app);
  await app.init();
  authz = app.get(AuthorizationService);
});

afterAll(async () => {
  await app?.close();
  await ds?.destroy();
});

describe('AuthorizationService.can (BD real)', () => {
  it('ADMIN de la seed tiene todos los permisos de la matriz §5', async () => {
    const id = await adminId();
    for (const p of [
      'profile.read',
      'users.manage',
      'roles.manage',
      'user_roles.manage',
      'steganography.analyze',
      'steganography.results.read_own',
      'steganography.results.read_any',
    ]) {
      await expect(authz.can(id, p)).resolves.toBe(true);
    }
  });

  it('USER solo tiene profile.read', async () => {
    const id = await createUser('solo_user', ['USER']);
    await expect(authz.can(id, 'profile.read')).resolves.toBe(true);
    await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(false);
    await expect(authz.can(id, 'users.manage')).resolves.toBe(false);
  });

  it('ANALYST no tiene read_any ni permisos de administración', async () => {
    const id = await createUser('analista', ['ANALYST']);
    await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(true);
    await expect(authz.can(id, 'steganography.results.read_own')).resolves.toBe(
      true,
    );
    await expect(authz.can(id, 'steganography.results.read_any')).resolves.toBe(
      false,
    );
    await expect(authz.can(id, 'user_roles.manage')).resolves.toBe(false);
  });

  it('varios roles → unión de permisos', async () => {
    const id = await createUser('dos_roles', ['USER', 'ANALYST']);
    await expect(authz.can(id, 'profile.read')).resolves.toBe(true);
    await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(true);
  });

  it('usuario sin asignaciones → deniega todo', async () => {
    const id = await createUser('sin_asignacion');
    await expect(authz.can(id, 'profile.read')).resolves.toBe(false);
  });

  it('T07: quitar la asignación deniega en la consulta siguiente', async () => {
    const id = await createUser('revocado', ['ANALYST']);
    await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(true);
    await unassign(id, 'ANALYST');
    await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(false);
  });

  it('rol inactivo → deniega; al reactivarlo vuelve a conceder', async () => {
    const id = await createUser('rol_inactivo', ['ANALYST']);
    await ds.query(
      `UPDATE roles SET status = 'inactive' WHERE name = 'ANALYST'`,
    );
    try {
      await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(false);
    } finally {
      await ds.query(
        `UPDATE roles SET status = 'active' WHERE name = 'ANALYST'`,
      );
    }
    await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(true);
  });

  it('usuario inactivo → deniega aunque tenga el rol', async () => {
    const id = await createUser('user_inactivo', ['ANALYST']);
    await ds.query(`UPDATE users SET status = 'inactive' WHERE id = $1`, [id]);
    await expect(authz.can(id, 'steganography.analyze')).resolves.toBe(false);
  });

  it('permiso inexistente, UUID desconocido o id no UUID → deniega sin error', async () => {
    const id = await adminId();
    await expect(authz.can(id, 'permiso.inventado')).resolves.toBe(false);
    await expect(authz.can(UNKNOWN_UUID, 'profile.read')).resolves.toBe(false);
    await expect(authz.can('no-es-uuid', 'profile.read')).resolves.toBe(false);
    await expect(authz.can(id, "profile.read' OR '1'='1")).resolves.toBe(false);
  });
});

describe('PermissionsGuard en GET /api/auth/profile (profile.read)', () => {
  async function token(username: string): Promise<string> {
    const res = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ username, password: PASSWORD })
      .expect(200);
    return (res.body as { access_token: string }).access_token;
  }

  it('usuario autenticado sin rol → 403 genérico; con USER (mismo token) → 200', async () => {
    const id = await createUser('perfil_sin_rol');
    const t = await token('perfil_sin_rol');

    const denied = await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${t}`)
      .expect(403);
    expect(denied.body).toEqual({
      statusCode: 403,
      message: 'Permiso denegado',
    });

    await assign(id, 'USER');
    await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${t}`)
      .expect(200);
  });

  it('sin token → 401 (antes que 403)', async () => {
    await request(app.getHttpServer()).get('/api/auth/profile').expect(401);
  });
});
