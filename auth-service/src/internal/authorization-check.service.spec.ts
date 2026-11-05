import type { Repository } from 'typeorm';
import type { AuthorizationService } from '../auth/authorization.service.js';
import type { AccessClaims, TokenService } from '../auth/token.service.js';
import type { RevokedToken } from '../database/entities/revoked-token.entity.js';
import type { User } from '../database/entities/user.entity.js';
import { AuthorizationCheckService } from './authorization-check.service.js';

const SUB = '11111111-1111-4111-8111-111111111111';
const JTI = '22222222-2222-4222-8222-222222222222';
const VALID = 'valid.jwt.token';

interface World {
  userStatus?: 'active' | 'inactive' | null; // null → no existe
  revoked?: boolean;
  perms?: string[];
}

function build(w: World = {}) {
  const calls = { db: 0, can: [] as string[] };
  const tokens = {
    verify: (t: string): Promise<AccessClaims> =>
      t === VALID
        ? Promise.resolve({ sub: SUB, jti: JTI, exp: 9999999999 })
        : Promise.reject(new Error('bad')),
  } as unknown as TokenService;
  const authz = {
    can: (id: string, p: string) => {
      calls.can.push(p);
      return Promise.resolve(id === SUB && (w.perms ?? []).includes(p));
    },
  } as unknown as AuthorizationService;
  const status = w.userStatus === undefined ? 'active' : w.userStatus;
  const users = {
    findOne: () => {
      calls.db++;
      return Promise.resolve(status === null ? null : { id: SUB, status });
    },
  } as unknown as Repository<User>;
  const revoked = {
    existsBy: () => {
      calls.db++;
      return Promise.resolve(w.revoked ?? false);
    },
  } as unknown as Repository<RevokedToken>;
  const svc = new AuthorizationCheckService(tokens, authz, users, revoked);
  return { svc, calls };
}

const ANALYZE = 'steganography.analyze';
const READ = 'steganography.results.read';

describe('AuthorizationCheckService.check', () => {
  it('JWT inválido → invalid_subject_token, subject_id null y sin tocar la BD', async () => {
    const { svc, calls } = build({ perms: [ANALYZE] });
    await expect(svc.check('forged.jwt.x', ANALYZE)).resolves.toEqual({
      subject_id: null,
      action: ANALYZE,
      allowed: false,
      reason: 'invalid_subject_token',
      can_read_any: false,
    });
    expect(calls.db).toBe(0);
    expect(calls.can).toEqual([]);
  });

  it('usuario inexistente → invalid_subject_token', async () => {
    const { svc } = build({ userStatus: null, perms: [ANALYZE] });
    await expect(svc.check(VALID, ANALYZE)).resolves.toMatchObject({
      allowed: false,
      reason: 'invalid_subject_token',
    });
  });

  it('jti revocado → token_revoked', async () => {
    const { svc } = build({ revoked: true, perms: [ANALYZE] });
    await expect(svc.check(VALID, ANALYZE)).resolves.toEqual({
      subject_id: SUB,
      action: ANALYZE,
      allowed: false,
      reason: 'token_revoked',
      can_read_any: false,
    });
  });

  it('usuario inactivo → user_inactive', async () => {
    const { svc } = build({ userStatus: 'inactive', perms: [ANALYZE] });
    await expect(svc.check(VALID, ANALYZE)).resolves.toMatchObject({
      allowed: false,
      reason: 'user_inactive',
    });
  });

  it('acción desconocida → unknown_action sin consultar permisos', async () => {
    const { svc, calls } = build({ perms: ['users.manage'] });
    await expect(svc.check(VALID, 'users.manage')).resolves.toEqual({
      subject_id: SUB,
      action: 'users.manage',
      allowed: false,
      reason: 'unknown_action',
      can_read_any: false,
    });
    expect(calls.can).toEqual([]);
  });

  it('analyze con permiso → active_role_grants_permission', async () => {
    const { svc } = build({ perms: [ANALYZE] });
    await expect(svc.check(VALID, ANALYZE)).resolves.toEqual({
      subject_id: SUB,
      action: ANALYZE,
      allowed: true,
      reason: 'active_role_grants_permission',
      can_read_any: false,
    });
  });

  it('analyze sin permiso → no_active_role_grants_permission', async () => {
    const { svc } = build({ perms: ['profile.read'] });
    await expect(svc.check(VALID, ANALYZE)).resolves.toMatchObject({
      allowed: false,
      reason: 'no_active_role_grants_permission',
    });
  });

  it('results.read con read_own → allowed, can_read_any false', async () => {
    const { svc } = build({ perms: ['steganography.results.read_own'] });
    await expect(svc.check(VALID, READ)).resolves.toMatchObject({
      allowed: true,
      reason: 'active_role_grants_permission',
      can_read_any: false,
    });
  });

  it('results.read con read_any → allowed, can_read_any true', async () => {
    const { svc } = build({
      perms: [
        'steganography.results.read_own',
        'steganography.results.read_any',
      ],
    });
    await expect(svc.check(VALID, READ)).resolves.toMatchObject({
      allowed: true,
      can_read_any: true,
    });
  });

  it('results.read sin permisos → denegado', async () => {
    const { svc } = build({ perms: ['profile.read'] });
    await expect(svc.check(VALID, READ)).resolves.toMatchObject({
      allowed: false,
      reason: 'no_active_role_grants_permission',
      can_read_any: false,
    });
  });
});
