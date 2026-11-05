import type { Request } from 'express';

/** Lo que JwtAuthGuard deja en `req.user`: solo identidad. Los permisos se consultan en BD. */
export interface AuthUser {
  id: string;
  jti: string;
  exp: number;
}

export type AuthenticatedRequest = Request & { user: AuthUser };
