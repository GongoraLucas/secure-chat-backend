import { type ExecutionContext, UnauthorizedException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { Env } from '../config/env.schema.js';
import { ServiceTokenGuard } from './service-token.guard.js';

const SECRET = 's'.repeat(40);

function guard(): ServiceTokenGuard {
  const config = { get: () => SECRET } as unknown as ConfigService<Env, true>;
  return new ServiceTokenGuard(config);
}

function ctx(headers: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers, ip: '10.0.0.9' }) }),
  } as unknown as ExecutionContext;
}

describe('ServiceTokenGuard (X-Service-Token)', () => {
  it('acepta el token de servicio correcto', () => {
    expect(guard().canActivate(ctx({ 'x-service-token': SECRET }))).toBe(true);
  });

  it.each([
    ['ausente', {}],
    ['vacío', { 'x-service-token': '' }],
    ['misma longitud, distinto', { 'x-service-token': 't'.repeat(40) }],
    ['longitud distinta', { 'x-service-token': SECRET + 'x' }],
    ['prefijo del secreto', { 'x-service-token': SECRET.slice(0, 32) }],
    ['cabecera repetida (array)', { 'x-service-token': [SECRET, SECRET] }],
  ])('rechaza con 401: %s', (_name, headers) => {
    expect(() => guard().canActivate(ctx(headers))).toThrow(
      UnauthorizedException,
    );
  });
});
