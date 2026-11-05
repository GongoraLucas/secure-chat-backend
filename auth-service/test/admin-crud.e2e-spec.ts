import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as argon2 from 'argon2';
import request from 'supertest';
import { App } from 'supertest/types.js';
import { DataSource } from 'typeorm';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/common/app-setup.js';
import { validateEnv } from '../src/config/env.schema.js';
import { runSeed } from '../src/database/seeds/seed.js';
import { buildDataSourceOptions } from '../src/database/typeorm-options.js';

/**
 * A5 · CRUD de users, roles y user-roles solo para ADMIN (§2, §5, §11) [T05, T06].
 * Contra Postgres real (../scripts/test-db.sh up).
 */

const env = validateEnv(process.env);
const PASSWORD = 'Admin-Crud-Pass-1234';
const UNKNOWN_UUID = '00000000-0000-4000-8000-000000000000';

let ds: DataSource;
let app: INestApplication<App>;
let hash: string;
let adminToken: string;
let userToken: string;
let analystToken: string;

async function createUser(username: string, roles: string[]) {
  const [{ id }] = (await ds.query(
    `INSERT INTO users (username, email, password_hash)
     VALUES ($1, $2, $3) RETURNING id`,
    [username, `${username}@example.com`, hash],
  )) as Array<{ id: string }>;
  for (const role of roles) {
    await ds.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT $1, id FROM roles WHERE name = $2`,
      [id, role],
    );
  }
  return id;
}

async function login(username: string, password = PASSWORD) {
  const res = await request(app.getHttpServer())
    .post('/api/auth/login')
    .send({ username, password });
  return res;
}

async function tokenFor(username: string): Promise<string> {
  const res = await login(username);
  expect(res.status).toBe(200);
  return (res.body as { access_token: string }).access_token;
}

async function roleId(name: string): Promise<string> {
  const [{ id }] = (await ds.query(`SELECT id FROM roles WHERE name = $1`, [
    name,
  ])) as Array<{ id: string }>;
  return id;
}

const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

beforeAll(async () => {
  ds = new DataSource(buildDataSourceOptions(env));
  await ds.initialize();
  await ds.dropDatabase();
  await ds.runMigrations();
  await runSeed(ds, env);
  hash = await argon2.hash(PASSWORD, { type: argon2.argon2id });

  await createUser('crud_admin', ['ADMIN']);
  await createUser('crud_user', ['USER']);
  await createUser('crud_analyst', ['ANALYST']);

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();
  app = moduleRef.createNestApplication<INestApplication<App>>();
  configureApp(app);
  await app.init();

  adminToken = await tokenFor('crud_admin');
  userToken = await tokenFor('crud_user');
  analystToken = await tokenFor('crud_analyst');
});

afterAll(async () => {
  await app?.close();
  await ds?.destroy();
});

describe('T05 · 401 sin token y 403 sin permiso en las 7 rutas', () => {
  const routes: Array<[string, string, object | null]> = [
    ['get', '/api/users', null],
    ['post', '/api/users', { username: 'x', email: 'x@e.com', password: 'p' }],
    ['patch', `/api/users/${UNKNOWN_UUID}`, { status: 'inactive' }],
    ['get', '/api/roles', null],
    ['post', '/api/roles', { name: 'X', description: 'x' }],
    ['patch', `/api/roles/${UNKNOWN_UUID}`, { description: 'x' }],
    [
      'post',
      '/api/user-roles',
      { user_id: UNKNOWN_UUID, role_id: UNKNOWN_UUID },
    ],
    ['delete', `/api/user-roles/${UNKNOWN_UUID}`, null],
  ];

  it.each(routes)('%s %s → 401 sin token', async (method, path, body) => {
    const req = request(app.getHttpServer())[
      method as 'get' | 'post' | 'patch' | 'delete'
    ](path);
    const res = await (body ? req.send(body) : req);
    expect(res.status).toBe(401);
  });

  it.each(routes)(
    '%s %s → 403 para USER y ANALYST',
    async (method, path, body) => {
      for (const t of [userToken, analystToken]) {
        const req = request(app.getHttpServer())
          [method as 'get' | 'post' | 'patch' | 'delete'](path)
          .set(bearer(t));
        const res = await (body ? req.send(body) : req);
        expect(res.status).toBe(403);
      }
    },
  );
});

describe('users', () => {
  it('GET lista con roles [{assignment_id, role_id, name}] y sin password_hash', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/users')
      .set(bearer(adminToken));
    expect(res.status).toBe(200);
    const users = res.body as Array<Record<string, unknown>>;
    const analyst = users.find((u) => u.username === 'crud_analyst');
    expect(analyst).toBeDefined();
    expect(Object.keys(analyst!).sort()).toEqual(
      [
        'created_at',
        'email',
        'id',
        'roles',
        'status',
        'updated_at',
        'username',
      ].sort(),
    );
    const roles = analyst!.roles as Array<Record<string, string>>;
    expect(roles).toHaveLength(1);
    expect(roles[0].name).toBe('ANALYST');
    expect(Object.keys(roles[0]).sort()).toEqual(
      ['assignment_id', 'name', 'role_id'].sort(),
    );
    expect(JSON.stringify(res.body)).not.toMatch(/argon2|password/i);
  });

  it('POST crea usuario (201, sin hash) que guarda argon2id y puede loguear', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/users')
      .set(bearer(adminToken))
      .send({
        username: 'nuevo',
        email: 'nuevo@example.com',
        password: 'Nuevo-Pass-12345',
      });
    expect(res.status).toBe(201);
    const body = res.body as Record<string, unknown>;
    expect(body).toMatchObject({
      username: 'nuevo',
      email: 'nuevo@example.com',
      status: 'active',
    });
    expect(body).not.toHaveProperty('password');
    expect(body).not.toHaveProperty('password_hash');

    const [row] = (await ds.query(
      `SELECT password_hash FROM users WHERE username = 'nuevo'`,
    )) as Array<{ password_hash: string }>;
    expect(row.password_hash.startsWith('$argon2id$')).toBe(true);
    expect((await login('nuevo', 'Nuevo-Pass-12345')).status).toBe(200);
  });

  it('POST con contraseña < 12 caracteres → 400', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/users')
      .set(bearer(adminToken))
      .send({ username: 'corto', email: 'corto@example.com', password: 'abc' });
    expect(res.status).toBe(400);
  });

  it('POST con campo extra → 400', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/users')
      .set(bearer(adminToken))
      .send({
        username: 'extra',
        email: 'extra@example.com',
        password: 'Extra-Pass-12345',
        status: 'inactive',
        id: UNKNOWN_UUID,
      });
    expect(res.status).toBe(400);
  });

  it('POST con username o email duplicado → 409', async () => {
    const dupUser = await request(app.getHttpServer())
      .post('/api/users')
      .set(bearer(adminToken))
      .send({
        username: 'nuevo',
        email: 'otro@example.com',
        password: 'Nuevo-Pass-12345',
      });
    expect(dupUser.status).toBe(409);
    const dupMail = await request(app.getHttpServer())
      .post('/api/users')
      .set(bearer(adminToken))
      .send({
        username: 'otro',
        email: 'nuevo@example.com',
        password: 'Nuevo-Pass-12345',
      });
    expect(dupMail.status).toBe(409);
  });

  it('PATCH cambia email, password y status; inactive bloquea el login', async () => {
    const [{ id }] = (await ds.query(
      `SELECT id FROM users WHERE username = 'nuevo'`,
    )) as Array<{ id: string }>;

    const res = await request(app.getHttpServer())
      .patch(`/api/users/${id}`)
      .set(bearer(adminToken))
      .send({ email: 'cambiado@example.com', password: 'Cambiada-Pass-123' });
    expect(res.status).toBe(200);
    expect((res.body as { email: string }).email).toBe('cambiado@example.com');
    expect(res.body).not.toHaveProperty('password_hash');
    expect((await login('nuevo', 'Nuevo-Pass-12345')).status).toBe(401);
    expect((await login('nuevo', 'Cambiada-Pass-123')).status).toBe(200);

    const off = await request(app.getHttpServer())
      .patch(`/api/users/${id}`)
      .set(bearer(adminToken))
      .send({ status: 'inactive' });
    expect(off.status).toBe(200);
    expect((off.body as { status: string }).status).toBe('inactive');
    expect((await login('nuevo', 'Cambiada-Pass-123')).status).toBe(401);
  });

  it('PATCH con id inexistente → 404, con id mal formado → 400, status inválido → 400', async () => {
    const missing = await request(app.getHttpServer())
      .patch(`/api/users/${UNKNOWN_UUID}`)
      .set(bearer(adminToken))
      .send({ status: 'inactive' });
    expect(missing.status).toBe(404);
    const badId = await request(app.getHttpServer())
      .patch('/api/users/no-es-uuid')
      .set(bearer(adminToken))
      .send({ status: 'inactive' });
    expect(badId.status).toBe(400);
    const badStatus = await request(app.getHttpServer())
      .patch(`/api/users/${UNKNOWN_UUID}`)
      .set(bearer(adminToken))
      .send({ status: 'banned' });
    expect(badStatus.status).toBe(400);
  });
});

describe('roles', () => {
  it('GET lista [{id, name, description, status}]', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/roles')
      .set(bearer(adminToken));
    expect(res.status).toBe(200);
    const roles = res.body as Array<Record<string, unknown>>;
    expect(roles.map((r) => r.name)).toEqual(
      expect.arrayContaining(['ADMIN', 'ANALYST', 'USER']),
    );
    expect(Object.keys(roles[0]).sort()).toEqual(
      ['description', 'id', 'name', 'status'].sort(),
    );
  });

  it('POST crea (201), duplicado → 409, sin nombre → 400', async () => {
    const ok = await request(app.getHttpServer())
      .post('/api/roles')
      .set(bearer(adminToken))
      .send({ name: 'AUDITOR', description: 'Solo lectura' });
    expect(ok.status).toBe(201);
    expect(ok.body).toMatchObject({
      name: 'AUDITOR',
      description: 'Solo lectura',
      status: 'active',
    });
    const dup = await request(app.getHttpServer())
      .post('/api/roles')
      .set(bearer(adminToken))
      .send({ name: 'AUDITOR', description: 'otra' });
    expect(dup.status).toBe(409);
    const bad = await request(app.getHttpServer())
      .post('/api/roles')
      .set(bearer(adminToken))
      .send({ description: 'sin nombre' });
    expect(bad.status).toBe(400);
  });

  it('PATCH cambia description/status; inexistente → 404; name no editable → 400', async () => {
    const id = await roleId('AUDITOR');
    const ok = await request(app.getHttpServer())
      .patch(`/api/roles/${id}`)
      .set(bearer(adminToken))
      .send({ description: 'Nueva', status: 'inactive' });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({
      id,
      description: 'Nueva',
      status: 'inactive',
    });
    const missing = await request(app.getHttpServer())
      .patch(`/api/roles/${UNKNOWN_UUID}`)
      .set(bearer(adminToken))
      .send({ description: 'x' });
    expect(missing.status).toBe(404);
    const rename = await request(app.getHttpServer())
      .patch(`/api/roles/${id}`)
      .set(bearer(adminToken))
      .send({ name: 'OTRO' });
    expect(rename.status).toBe(400);
  });
});

describe('user-roles · T06', () => {
  it('POST asigna (201), duplicado → 409; DELETE revoca (204) y luego 404', async () => {
    const [{ id: userId }] = (await ds.query(
      `SELECT id FROM users WHERE username = 'crud_user'`,
    )) as Array<{ id: string }>;
    const analyst = await roleId('ANALYST');

    const ok = await request(app.getHttpServer())
      .post('/api/user-roles')
      .set(bearer(adminToken))
      .send({ user_id: userId, role_id: analyst });
    expect(ok.status).toBe(201);
    const body = ok.body as Record<string, string>;
    expect(Object.keys(body).sort()).toEqual(
      ['assigned_at', 'id', 'role_id', 'user_id'].sort(),
    );
    expect(body.user_id).toBe(userId);
    expect(body.role_id).toBe(analyst);

    const dup = await request(app.getHttpServer())
      .post('/api/user-roles')
      .set(bearer(adminToken))
      .send({ user_id: userId, role_id: analyst });
    expect(dup.status).toBe(409);

    const del = await request(app.getHttpServer())
      .delete(`/api/user-roles/${body.id}`)
      .set(bearer(adminToken));
    expect(del.status).toBe(204);
    const again = await request(app.getHttpServer())
      .delete(`/api/user-roles/${body.id}`)
      .set(bearer(adminToken));
    expect(again.status).toBe(404);
  });

  it('POST con usuario o rol inexistente → 404; uuid inválido → 400', async () => {
    const analyst = await roleId('ANALYST');
    const [{ id: userId }] = (await ds.query(
      `SELECT id FROM users WHERE username = 'crud_user'`,
    )) as Array<{ id: string }>;
    const noUser = await request(app.getHttpServer())
      .post('/api/user-roles')
      .set(bearer(adminToken))
      .send({ user_id: UNKNOWN_UUID, role_id: analyst });
    expect(noUser.status).toBe(404);
    const noRole = await request(app.getHttpServer())
      .post('/api/user-roles')
      .set(bearer(adminToken))
      .send({ user_id: userId, role_id: UNKNOWN_UUID });
    expect(noRole.status).toBe(404);
    const bad = await request(app.getHttpServer())
      .post('/api/user-roles')
      .set(bearer(adminToken))
      .send({ user_id: 'x', role_id: 'y' });
    expect(bad.status).toBe(400);
  });

  it('DELETE con id mal formado → 400', async () => {
    const res = await request(app.getHttpServer())
      .delete('/api/user-roles/no-es-uuid')
      .set(bearer(adminToken));
    expect(res.status).toBe(400);
  });

  it('efecto inmediato: tras revocar ADMIN, el mismo JWT recibe 403', async () => {
    await createUser('temp_admin', ['ADMIN']);
    const t = await tokenFor('temp_admin');
    const list = await request(app.getHttpServer())
      .get('/api/users')
      .set(bearer(t));
    expect(list.status).toBe(200);

    const [{ id }] = (await ds.query(
      `SELECT ur.id FROM user_roles ur JOIN users u ON u.id = ur.user_id
       WHERE u.username = 'temp_admin'`,
    )) as Array<{ id: string }>;
    const del = await request(app.getHttpServer())
      .delete(`/api/user-roles/${id}`)
      .set(bearer(adminToken));
    expect(del.status).toBe(204);

    const after = await request(app.getHttpServer())
      .get('/api/users')
      .set(bearer(t));
    expect(after.status).toBe(403);
  });
});
