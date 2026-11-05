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
 * A7 · POST /internal/authorization/check (§6, §11) contra Postgres real
 * (../scripts/test-db.sh up). Cubre T04 y T07 a nivel de AUTH.
 */

const env = validateEnv(process.env);
const PASSWORD = 'Internal-Test-Pass-1234';
const ANALYZE = 'steganography.analyze';
const READ = 'steganography.results.read';
const UUID_RE = /^[0-9a-f-]{36}$/;

let ds: DataSource;
let app: INestApplication<App>;
let hash: string;

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

async function login(username: string, password = PASSWORD): Promise<string> {
  const res = await request(app.getHttpServer())
    .post('/api/auth/login')
    .send({ username, password })
    .expect(200);
  return (res.body as { access_token: string }).access_token;
}

function check(body: object, serviceToken: string | null = env.SERVICE_TOKEN) {
  const req = request(app.getHttpServer()).post(
    '/internal/authorization/check',
  );
  if (serviceToken !== null) req.set('X-Service-Token', serviceToken);
  return req.send(body);
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
});

afterAll(async () => {
  await app?.close();
  await ds?.destroy();
});

describe('POST /internal/authorization/check (e2e)', () => {
  let analystId: string;
  let analystToken: string;

  beforeAll(async () => {
    analystId = await createUser('int_analyst', ['ANALYST']);
    analystToken = await login('int_analyst');
  });

  it('sin X-Service-Token → 401 {statusCode, message}', async () => {
    const res = await check(
      { subject_token: analystToken, action: ANALYZE, resource_id: null },
      null,
    ).expect(401);
    expect(res.body).toEqual({ statusCode: 401, message: expect.any(String) });
  });

  it('X-Service-Token erróneo → 401 (antes de validar el cuerpo)', async () => {
    await check({ basura: true }, 'x'.repeat(32)).expect(401);
  });

  it('cuerpo inválido o con campos extra → 400', async () => {
    await check({ action: ANALYZE }).expect(400);
    await check({
      subject_token: analystToken,
      action: ANALYZE,
      allowed: true,
    }).expect(400);
  });

  it('ANALYST + analyze → 200 allowed con la forma de §11', async () => {
    const res = await check({
      subject_token: analystToken,
      action: ANALYZE,
      resource_id: null,
    }).expect(200);
    expect(res.body).toEqual({
      subject_id: analystId,
      action: ANALYZE,
      allowed: true,
      reason: 'active_role_grants_permission',
      can_read_any: false,
    });
  });

  it('T04: USER + analyze → allowed:false no_active_role_grants_permission', async () => {
    await createUser('int_user', ['USER']);
    const token = await login('int_user');
    const res = await check({ subject_token: token, action: ANALYZE }).expect(
      200,
    );
    expect(res.body).toMatchObject({
      subject_id: expect.stringMatching(UUID_RE),
      allowed: false,
      reason: 'no_active_role_grants_permission',
    });
  });

  it('T07: quitar el rol y reusar el mismo JWT → denegado', async () => {
    const id = await createUser('int_t07', ['ANALYST']);
    const token = await login('int_t07');
    await check({ subject_token: token, action: ANALYZE })
      .expect(200)
      .expect((r) => expect(r.body).toMatchObject({ allowed: true }));
    await ds.query(`DELETE FROM user_roles WHERE user_id = $1`, [id]);
    const res = await check({ subject_token: token, action: ANALYZE }).expect(
      200,
    );
    expect(res.body).toMatchObject({
      subject_id: id,
      allowed: false,
      reason: 'no_active_role_grants_permission',
    });
  });

  it('tras logout → token_revoked', async () => {
    await createUser('int_logout', ['ANALYST']);
    const token = await login('int_logout');
    await request(app.getHttpServer())
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`)
      .expect(204);
    const res = await check({ subject_token: token, action: ANALYZE }).expect(
      200,
    );
    expect(res.body).toMatchObject({ allowed: false, reason: 'token_revoked' });
  });

  it('usuario desactivado con JWT vigente → user_inactive', async () => {
    const id = await createUser('int_inactive', ['ANALYST']);
    const token = await login('int_inactive');
    await ds.query(`UPDATE users SET status = 'inactive' WHERE id = $1`, [id]);
    const res = await check({ subject_token: token, action: ANALYZE }).expect(
      200,
    );
    expect(res.body).toMatchObject({ allowed: false, reason: 'user_inactive' });
  });

  it('JWT manipulado o basura → invalid_subject_token, subject_id null', async () => {
    const [h, p, s] = analystToken.split('.');
    const tampered = `${h}.${p}.${s.slice(0, -4)}AAAA`;
    for (const t of [tampered, 'no-es-un-jwt']) {
      const res = await check({ subject_token: t, action: ANALYZE }).expect(
        200,
      );
      expect(res.body).toEqual({
        subject_id: null,
        action: ANALYZE,
        allowed: false,
        reason: 'invalid_subject_token',
        can_read_any: false,
      });
    }
  });

  it('acción desconocida → unknown_action', async () => {
    const res = await check({
      subject_token: analystToken,
      action: 'users.manage',
    }).expect(200);
    expect(res.body).toMatchObject({
      allowed: false,
      reason: 'unknown_action',
    });
  });

  it('results.read: ANALYST can_read_any=false, ADMIN can_read_any=true', async () => {
    await check({
      subject_token: analystToken,
      action: READ,
      resource_id: 'r1',
    })
      .expect(200)
      .expect((r) =>
        expect(r.body).toMatchObject({ allowed: true, can_read_any: false }),
      );
    const adminToken = await login(env.ADMIN_USERNAME, env.ADMIN_PASSWORD);
    await check({ subject_token: adminToken, action: READ })
      .expect(200)
      .expect((r) =>
        expect(r.body).toMatchObject({ allowed: true, can_read_any: true }),
      );
  });
});
