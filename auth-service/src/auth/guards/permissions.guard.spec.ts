import {
  type ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { AuthorizationService } from '../authorization.service.js';
import { RequirePermission } from '../decorators/require-permission.decorator.js';
import { PermissionsGuard } from './permissions.guard.js';

/** Controlador ficticio: el guard lee la metadata real del decorador. */
@RequirePermission('roles.manage')
class FakeController {
  @RequirePermission('users.manage')
  withPermission(this: void) {}

  inheritsFromClass(this: void) {}
}

class NoMetadataController {
  unprotected(this: void) {}
}

const USER_ID = '11111111-1111-4111-8111-111111111111';

function ctx(
  handler: () => void,
  cls: object,
  req: Record<string, unknown>,
): ExecutionContext {
  return {
    getHandler: () => handler,
    getClass: () => cls,
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

/** AuthorizationService falso que registra las llamadas y concede solo lo indicado. */
function fakeAuthz(granted: Record<string, string[]>) {
  const calls: Array<[string, string]> = [];
  const authz = {
    can: (userId: string, permission: string) => {
      calls.push([userId, permission]);
      return Promise.resolve(granted[userId]?.includes(permission) ?? false);
    },
  } as unknown as AuthorizationService;
  return { authz, calls };
}

function request(extra: Record<string, unknown> = {}) {
  return {
    method: 'GET',
    originalUrl: '/api/test',
    user: { id: USER_ID, jti: 'j', exp: 0 },
    headers: {},
    body: {},
    ...extra,
  };
}

describe('PermissionsGuard', () => {
  const reflector = new Reflector();
  const proto = FakeController.prototype;

  it('concede si AuthorizationService confirma el permiso del handler', async () => {
    const { authz, calls } = fakeAuthz({ [USER_ID]: ['users.manage'] });
    const guard = new PermissionsGuard(reflector, authz);
    await expect(
      guard.canActivate(ctx(proto.withPermission, FakeController, request())),
    ).resolves.toBe(true);
    expect(calls).toEqual([[USER_ID, 'users.manage']]);
  });

  it('sin el permiso → 403', async () => {
    const { authz } = fakeAuthz({ [USER_ID]: ['profile.read'] });
    const guard = new PermissionsGuard(reflector, authz);
    await expect(
      guard.canActivate(ctx(proto.withPermission, FakeController, request())),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('usa el permiso de la clase si el handler no declara uno', async () => {
    const { authz, calls } = fakeAuthz({ [USER_ID]: ['roles.manage'] });
    const guard = new PermissionsGuard(reflector, authz);
    await expect(
      guard.canActivate(
        ctx(proto.inheritsFromClass, FakeController, request()),
      ),
    ).resolves.toBe(true);
    expect(calls).toEqual([[USER_ID, 'roles.manage']]);
  });

  it('deny by default: ruta con el guard pero sin @RequirePermission → 403 sin consultar', async () => {
    const { authz, calls } = fakeAuthz({ [USER_ID]: ['users.manage'] });
    const guard = new PermissionsGuard(reflector, authz);
    await expect(
      guard.canActivate(
        ctx(
          NoMetadataController.prototype.unprotected,
          NoMetadataController,
          request(),
        ),
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(calls).toEqual([]);
  });

  it('sin req.user (JwtAuthGuard no corrió) → 401 sin consultar', async () => {
    const { authz, calls } = fakeAuthz({ [USER_ID]: ['users.manage'] });
    const guard = new PermissionsGuard(reflector, authz);
    await expect(
      guard.canActivate(
        ctx(proto.withPermission, FakeController, request({ user: undefined })),
      ),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(calls).toEqual([]);
  });

  it('ignora roles/permisos enviados por el cliente en cabeceras o body', async () => {
    const { authz, calls } = fakeAuthz({});
    const guard = new PermissionsGuard(reflector, authz);
    const req = request({
      headers: { 'x-role': 'ADMIN', 'x-permissions': 'users.manage' },
      body: { roles: ['ADMIN'], permissions: ['users.manage'] },
      user: { id: USER_ID, jti: 'j', exp: 0, roles: ['ADMIN'] },
    });
    await expect(
      guard.canActivate(ctx(proto.withPermission, FakeController, req)),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(calls).toEqual([[USER_ID, 'users.manage']]);
  });

  it('el 403 tiene un mensaje genérico', async () => {
    const { authz } = fakeAuthz({});
    const guard = new PermissionsGuard(reflector, authz);
    await expect(
      guard.canActivate(ctx(proto.withPermission, FakeController, request())),
    ).rejects.toThrow('Permiso denegado');
  });
});
