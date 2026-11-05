import {
  randomUUID,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { jwtVerify, SignJWT } from 'jose';

/** Configuración del firmante. Las claves llegan como PEM (leídas de disco por AuthModule). */
export interface TokenConfig {
  privateKeyPem: string;
  publicKeyPem: string;
  issuer: string;
  audience: string;
  ttlSeconds: number;
}

/** Lo único que se usa de un token verificado. Sin roles: la autorización sale de la BD. */
export interface AccessClaims {
  sub: string;
  jti: string;
  exp: number;
}

export const TOKEN_CONFIG = Symbol('TOKEN_CONFIG');

const ALG = 'RS256';
const MAX_TTL_SECONDS = 900; // §4: exp ≤ 15 min
// users.id y revoked_tokens.jti son uuid: cualquier otra cosa se rechaza antes de tocar la BD.
export const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class TokenService {
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;

  constructor(private readonly cfg: TokenConfig) {
    if (
      !Number.isInteger(cfg.ttlSeconds) ||
      cfg.ttlSeconds < 1 ||
      cfg.ttlSeconds > MAX_TTL_SECONDS
    ) {
      throw new Error(
        `JWT_TTL_SECONDS debe estar entre 1 y ${MAX_TTL_SECONDS}`,
      );
    }
    this.privateKey = createPrivateKey(cfg.privateKeyPem);
    this.publicKey = createPublicKey(cfg.publicKeyPem);
    for (const k of [this.privateKey, this.publicKey]) {
      if (k.asymmetricKeyType !== 'rsa') {
        throw new Error('Las claves JWT deben ser RSA (RS256)');
      }
    }
  }

  async sign(userId: string): Promise<{ token: string; expiresIn: number }> {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: ALG, typ: 'JWT' })
      .setSubject(userId)
      .setIssuer(this.cfg.issuer)
      .setAudience(this.cfg.audience)
      .setJti(randomUUID())
      .setIssuedAt(now)
      .setExpirationTime(now + this.cfg.ttlSeconds)
      .sign(this.privateKey);
    return { token, expiresIn: this.cfg.ttlSeconds };
  }

  /** Lanza ante cualquier problema: alg distinto de RS256, firma, iss, aud, exp, sub o jti. */
  async verify(token: string): Promise<AccessClaims> {
    const { payload } = await jwtVerify(token, this.publicKey, {
      algorithms: [ALG],
      issuer: this.cfg.issuer,
      audience: this.cfg.audience,
      requiredClaims: ['sub', 'jti', 'iat', 'exp'],
    });
    const { sub, jti, exp } = payload;
    if (
      typeof sub !== 'string' ||
      !UUID.test(sub) ||
      typeof jti !== 'string' ||
      !UUID.test(jti) ||
      typeof exp !== 'number'
    ) {
      throw new Error('claims inválidos');
    }
    return { sub, jti, exp };
  }
}
