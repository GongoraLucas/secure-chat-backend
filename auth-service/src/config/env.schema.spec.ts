import { validateEnv } from './env.schema.js';

const valid = {
  DB_HOST: 'localhost',
  DB_USER: 'auth',
  DB_NAME: 'auth',
  DB_PASSWORD: 'super-secret-db-pass',
  JWT_PRIVATE_KEY_PATH: '/run/keys/private.pem',
  JWT_PUBLIC_KEY_PATH: '/run/keys/public.pem',
  JWT_ISSUER: 'auth-service',
  JWT_AUDIENCE: 'secure-chat',
  SERVICE_TOKEN: 'x'.repeat(32),
  ADMIN_EMAIL: 'admin@example.com',
  ADMIN_PASSWORD: 'Admin-Pass-1234',
};

describe('validateEnv', () => {
  it('acepta un entorno válido y aplica valores por defecto', () => {
    const env = validateEnv({ ...valid });
    expect(env.PORT).toBe(3000);
    expect(env.DB_PORT).toBe(5432);
    expect(env.JWT_TTL_SECONDS).toBe(900);
    expect(env.ADMIN_USERNAME).toBe('admin');
  });

  it('convierte números que llegan como string', () => {
    const env = validateEnv({ ...valid, PORT: '3100', JWT_TTL_SECONDS: '600' });
    expect(env.PORT).toBe(3100);
    expect(env.JWT_TTL_SECONDS).toBe(600);
  });

  it('rechaza JWT_TTL_SECONDS > 900 (exp ≤ 15 min)', () => {
    expect(() => validateEnv({ ...valid, JWT_TTL_SECONDS: '901' })).toThrow(
      /JWT_TTL_SECONDS/,
    );
  });

  it('rechaza SERVICE_TOKEN de menos de 32 caracteres', () => {
    expect(() => validateEnv({ ...valid, SERVICE_TOKEN: 'corto' })).toThrow(
      /SERVICE_TOKEN/,
    );
  });

  it('rechaza si falta una variable obligatoria', () => {
    const { DB_PASSWORD: _omit, ...rest } = valid;
    expect(() => validateEnv(rest)).toThrow(/DB_PASSWORD/);
  });

  it('rechaza ADMIN_EMAIL inválido', () => {
    expect(() => validateEnv({ ...valid, ADMIN_EMAIL: 'no-es-email' })).toThrow(
      /ADMIN_EMAIL/,
    );
  });

  it('el mensaje de error no filtra valores secretos', () => {
    const token = 'SECRETO-tok';
    const pwd = 'PWD-x';
    let msg = '';
    try {
      validateEnv({ ...valid, SERVICE_TOKEN: token, ADMIN_PASSWORD: pwd });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/SERVICE_TOKEN/);
    expect(msg).toMatch(/ADMIN_PASSWORD/);
    expect(msg).not.toContain(token);
    expect(msg).not.toContain(pwd);
  });
});
