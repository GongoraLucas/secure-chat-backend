import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as argon2 from 'argon2';
import { decodeJwt } from 'jose';
import request from 'supertest';
import { App } from 'supertest/types.js';
import { DataSource } from 'typeorm';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/common/app-setup.js';
import { validateEnv } from '../src/config/env.schema.js';
import { runSeed } from '../src/database/seeds/seed.js';
import { buildDataSourceOptions } from '../src/database/typeorm-options.js';

/**
 * A3 · Login + profile contra Postgres real (../scripts/test-db.sh up). Escenario T02.
 * §4: argon2id, mensaje genérico, JWT RS256, rate limit. §11: formato de respuestas.
 */

const env = validateEnv(process.env);
const ADMIN = { username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD };
const INACTIVE = { username: 'inactivo', password: 'Inactive-Pass-1234' };
let ds: DataSource;

async function createApp(): Promise<INestApplication<App>> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();
  const app = moduleRef.createNestApplication<INestApplication<App>>();
  configureApp(app);
  await app.init();
  return app;
}

function login(app: INestApplication<App>, body: object) {
  return request(app.getHttpServer()).post('/api/auth/login').send(body);
}

beforeAll(async () => {
  ds = new DataSource(buildDataSourceOptions(env));
  await ds.initialize();
  await ds.dropDatabase();
  await ds.runMigrations();
  await runSeed(ds, env);
  const hash = await argon2.hash(INACTIVE.password, { type: argon2.argon2id });
  await ds.query(
    `INSERT INTO users (username, email, password_hash, status)
     VALUES ($1, 'inactivo@example.com', $2, 'inactive')`,
    [INACTIVE.username, hash],
  );
});

afterAll(async () => {
  await ds?.destroy();
});

describe('POST /api/auth/login y GET /api/auth/profile (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    app = await createApp();
  });

  afterAll(async () => {
    await app?.close();
  });

  it('T02: credenciales válidas → 200 {access_token, token_type:"Bearer", expires_in}', async () => {
    const res = await login(app, ADMIN).expect(200);
    expect(Object.keys(res.body as object).sort()).toEqual(
      ['access_token', 'expires_in', 'token_type'].sort(),
    );
    expect(res.body).toMatchObject({ token_type: 'Bearer', expires_in: 900 });
    const p = decodeJwt((res.body as { access_token: string }).access_token);
    expect(p).toMatchObject({ iss: env.JWT_ISSUER, aud: env.JWT_AUDIENCE });
    expect(p.jti).toBeDefined();
    expect(p).not.toHaveProperty('roles');
  });

  it('T02: contraseña incorrecta, usuario inexistente e inactivo → mismo 401 genérico', async () => {
    const wrong = await login(app, { ...ADMIN, password: 'incorrecta-123456' });
    const ghost = await login(app, {
      username: 'no-existe',
      password: 'incorrecta-123456',
    });
    const inactive = await login(app, INACTIVE);
    for (const r of [wrong, ghost, inactive]) {
      expect(r.status).toBe(401);
      expect(r.text).not.toContain('access_token');
    }
    expect(ghost.body).toEqual(wrong.body);
    expect(inactive.body).toEqual(wrong.body);
    expect(wrong.body).toEqual({
      statusCode: 401,
      message: 'Credenciales inválidas',
    });
  });

  it('cuerpo inválido o con campos extra → 400 {statusCode, message} sin stack', async () => {
    const empty = await login(app, {}).expect(400);
    expect(empty.body).toHaveProperty('statusCode', 400);
    expect(empty.body).toHaveProperty('message');
    expect(empty.text).not.toMatch(/at .*\.(ts|js):\d+/);
    await login(app, { ...ADMIN, role: 'ADMIN' }).expect(400);
  });

  it('profile con token → 200 {id, username, email, status, roles:[name]} sin hash', async () => {
    const { body } = await login(app, ADMIN).expect(200);
    const token = (body as { access_token: string }).access_token;
    const res = await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(res.body).toEqual({
      id: decodeJwt(token).sub,
      username: ADMIN.username,
      email: env.ADMIN_EMAIL,
      status: 'active',
      roles: ['ADMIN'],
    });
    expect(res.text).not.toContain('password');
  });

  it('profile sin token o con token basura → 401', async () => {
    await request(app.getHttpServer()).get('/api/auth/profile').expect(401);
    await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', 'Bearer no.es.jwt')
      .expect(401);
    await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', 'Basic YWRtaW46eA==')
      .expect(401);
  });

  it('profile con jti revocado → 401', async () => {
    const { body } = await login(app, ADMIN).expect(200);
    const token = (body as { access_token: string }).access_token;
    const p = decodeJwt(token);
    await ds.query(
      `INSERT INTO revoked_tokens (jti, user_id, expires_at)
       VALUES ($1, $2, to_timestamp($3))`,
      [p.jti, p.sub, p.exp],
    );
    await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
  });

  it('profile de un usuario desactivado después de emitir el token → 401', async () => {
    const hash = await argon2.hash('Temp-User-Pass-1234', {
      type: argon2.argon2id,
    });
    await ds.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ('temporal', 'temporal@example.com', $1)`,
      [hash],
    );
    const { body } = await login(app, {
      username: 'temporal',
      password: 'Temp-User-Pass-1234',
    }).expect(200);
    const token = (body as { access_token: string }).access_token;
    await ds.query(
      `UPDATE users SET status = 'inactive' WHERE username = 'temporal'`,
    );
    await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
  });
});

describe('POST /api/auth/logout (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    app = await createApp(); // limitador del login limpio
  });

  afterAll(async () => {
    await app?.close();
  });

  async function token(): Promise<string> {
    const { body } = await login(app, ADMIN).expect(200);
    return (body as { access_token: string }).access_token;
  }

  function logout(bearer?: string) {
    const req = request(app.getHttpServer()).post('/api/auth/logout');
    return bearer ? req.set('Authorization', `Bearer ${bearer}`) : req;
  }

  it('sin token o con token basura → 401', async () => {
    await logout().expect(401);
    await logout('a.b.c').expect(401);
  });

  it('logout → 204 sin cuerpo y el jti queda en revoked_tokens hasta su exp', async () => {
    const t = await token();
    const p = decodeJwt(t);
    const res = await logout(t).expect(204);
    expect(res.text).toBe('');
    const rows: { user_id: string; exp: string }[] = await ds.query(
      `SELECT user_id, extract(epoch FROM expires_at)::bigint AS exp
       FROM revoked_tokens WHERE jti = $1`,
      [p.jti],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].user_id).toBe(p.sub);
    expect(Number(rows[0].exp)).toBe(p.exp);
  });

  it('el token revocado ya no sirve: profile 401 y segundo logout 401', async () => {
    const t = await token();
    await logout(t).expect(204);
    await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${t}`)
      .expect(401);
    await logout(t).expect(401);
  });

  it('solo se revoca ese jti: otro token del mismo usuario sigue válido', async () => {
    const a = await token();
    const b = await token();
    await logout(a).expect(204);
    await request(app.getHttpServer())
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${b}`)
      .expect(200);
  });
});

describe('rate limit del login (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    app = await createApp(); // almacenamiento del throttler limpio
  });

  afterAll(async () => {
    await app?.close();
  });

  it('el intento 11 en un minuto desde la misma IP → 429', async () => {
    const bad = { username: 'no-existe', password: 'incorrecta-123456' };
    for (let i = 0; i < 10; i++) {
      await login(app, bad).expect(401);
    }
    const res = await login(app, bad).expect(429);
    expect(res.body).toHaveProperty('statusCode', 429);
  });
});
