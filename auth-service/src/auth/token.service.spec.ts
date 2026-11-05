import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { SignJWT, UnsecuredJWT, decodeJwt, decodeProtectedHeader } from 'jose';
import { TokenService, type TokenConfig } from './token.service.js';

/** §4: JWT RS256, exp ≤ 15 min, sub/iss/aud/jti/iat; se rechaza cualquier otra cosa. */

function rsaPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return {
    privateKeyPem: privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

const keys = rsaPair();
const cfg: TokenConfig = {
  ...keys,
  issuer: 'auth-service',
  audience: 'secure-chat',
  ttlSeconds: 900,
};
const svc = new TokenService(cfg);
const USER_ID = randomUUID();

/** Firma un JWT RS256 arbitrario con la clave privada indicada. */
async function forge(
  claims: Record<string, unknown>,
  opts: { key?: string; iss?: string; aud?: string; exp?: number } = {},
): Promise<string> {
  const { createPrivateKey } = await import('node:crypto');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(opts.iss ?? cfg.issuer)
    .setAudience(opts.aud ?? cfg.audience)
    .setIssuedAt(now - 10)
    .setExpirationTime(opts.exp ?? now + 60)
    .sign(createPrivateKey(opts.key ?? keys.privateKeyPem));
}

describe('TokenService', () => {
  it('emite RS256 con sub, iss, aud, jti, iat y exp = iat + TTL (sin roles)', async () => {
    const { token, expiresIn } = await svc.sign(USER_ID);
    expect(expiresIn).toBe(900);
    expect(decodeProtectedHeader(token).alg).toBe('RS256');
    const p = decodeJwt(token);
    expect(p.sub).toBe(USER_ID);
    expect(p.iss).toBe('auth-service');
    expect(p.aud).toBe('secure-chat');
    expect(p.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(p.exp! - p.iat!).toBe(900);
    expect(p).not.toHaveProperty('roles');
  });

  it('cada token lleva un jti distinto', async () => {
    const a = decodeJwt((await svc.sign(USER_ID)).token).jti;
    const b = decodeJwt((await svc.sign(USER_ID)).token).jti;
    expect(a).not.toBe(b);
  });

  it('verifica su propio token y devuelve {sub, jti, exp}', async () => {
    const { token } = await svc.sign(USER_ID);
    const claims = await svc.verify(token);
    expect(claims.sub).toBe(USER_ID);
    expect(typeof claims.jti).toBe('string');
    expect(claims.exp).toBeGreaterThan(Date.now() / 1000);
  });

  it('rechaza alg "none"', async () => {
    const token = new UnsecuredJWT({ sub: USER_ID, jti: randomUUID() })
      .setIssuer(cfg.issuer)
      .setAudience(cfg.audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .encode();
    await expect(svc.verify(token)).rejects.toThrow();
  });

  it('rechaza HS256 firmado con la clave pública como secreto', async () => {
    const token = await new SignJWT({ sub: USER_ID, jti: randomUUID() })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(cfg.issuer)
      .setAudience(cfg.audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode(keys.publicKeyPem));
    await expect(svc.verify(token)).rejects.toThrow();
  });

  it('rechaza una firma de otra clave RSA', async () => {
    const other = rsaPair();
    const token = await forge(
      { sub: USER_ID, jti: randomUUID() },
      { key: other.privateKeyPem },
    );
    await expect(svc.verify(token)).rejects.toThrow();
  });

  it('rechaza iss o aud incorrectos', async () => {
    const claims = { sub: USER_ID, jti: randomUUID() };
    await expect(
      svc.verify(await forge(claims, { iss: 'evil' })),
    ).rejects.toThrow();
    await expect(
      svc.verify(await forge(claims, { aud: 'otro' })),
    ).rejects.toThrow();
  });

  it('rechaza un token expirado', async () => {
    const past = Math.floor(Date.now() / 1000) - 120;
    const token = await forge(
      { sub: USER_ID, jti: randomUUID() },
      { exp: past },
    );
    await expect(svc.verify(token)).rejects.toThrow();
  });

  it('rechaza un token sin jti o sin sub', async () => {
    await expect(svc.verify(await forge({ sub: USER_ID }))).rejects.toThrow();
    await expect(
      svc.verify(await forge({ jti: randomUUID() })),
    ).rejects.toThrow();
  });

  it('rechaza basura', async () => {
    await expect(svc.verify('no.es.jwt')).rejects.toThrow();
  });

  it('no arranca con un TTL > 900 s ni con una clave que no sea RSA', () => {
    expect(() => new TokenService({ ...cfg, ttlSeconds: 901 })).toThrow();
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    expect(
      () =>
        new TokenService({
          ...cfg,
          privateKeyPem: privateKey
            .export({ type: 'pkcs8', format: 'pem' })
            .toString(),
          publicKeyPem: publicKey
            .export({ type: 'spki', format: 'pem' })
            .toString(),
        }),
    ).toThrow();
  });
});
