import { type ExecutionContext, HttpException } from '@nestjs/common';
import { LoginRateLimitGuard } from './login-rate-limit.guard.js';

function ctx(ip: string): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ ip }) }),
  } as unknown as ExecutionContext;
}

describe('LoginRateLimitGuard', () => {
  it('deja pasar `limit` intentos por IP y el siguiente → 429', () => {
    let now = 0;
    const guard = new LoginRateLimitGuard({
      limit: 3,
      windowMs: 60_000,
      now: () => now,
    });
    for (let i = 0; i < 3; i++)
      expect(guard.canActivate(ctx('1.1.1.1'))).toBe(true);
    try {
      guard.canActivate(ctx('1.1.1.1'));
      throw new Error('no lanzó');
    } catch (e) {
      expect(e).toBeInstanceOf(HttpException);
      expect((e as HttpException).getStatus()).toBe(429);
    }
  });

  it('cuenta cada IP por separado', () => {
    const guard = new LoginRateLimitGuard({
      limit: 1,
      windowMs: 60_000,
      now: () => 0,
    });
    expect(guard.canActivate(ctx('1.1.1.1'))).toBe(true);
    expect(guard.canActivate(ctx('2.2.2.2'))).toBe(true);
    expect(() => guard.canActivate(ctx('1.1.1.1'))).toThrow(HttpException);
  });

  it('la ventana se reinicia al pasar windowMs', () => {
    let now = 0;
    const guard = new LoginRateLimitGuard({
      limit: 1,
      windowMs: 60_000,
      now: () => now,
    });
    expect(guard.canActivate(ctx('1.1.1.1'))).toBe(true);
    expect(() => guard.canActivate(ctx('1.1.1.1'))).toThrow(HttpException);
    now = 60_000;
    expect(guard.canActivate(ctx('1.1.1.1'))).toBe(true);
  });

  it('sin IP conocida también se limita (clave común)', () => {
    const guard = new LoginRateLimitGuard({
      limit: 1,
      windowMs: 60_000,
      now: () => 0,
    });
    expect(guard.canActivate(ctx(undefined as unknown as string))).toBe(true);
    expect(() =>
      guard.canActivate(ctx(undefined as unknown as string)),
    ).toThrow(HttpException);
  });
});
