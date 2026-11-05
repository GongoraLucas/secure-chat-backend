import { z } from 'zod';

/** Variables de entorno de AUTH. Si alguna falta o es inválida, el proceso no arranca. */
export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  DB_HOST: z.string().min(1),
  DB_PORT: z.coerce.number().int().min(1).max(65535).default(5432),
  DB_USER: z.string().min(1),
  DB_NAME: z.string().min(1),
  DB_PASSWORD: z.string().min(1),

  JWT_PRIVATE_KEY_PATH: z.string().min(1),
  JWT_PUBLIC_KEY_PATH: z.string().min(1),
  JWT_ISSUER: z.string().min(1),
  JWT_AUDIENCE: z.string().min(1),
  JWT_TTL_SECONDS: z.coerce.number().int().min(1).max(900).default(900),

  SERVICE_TOKEN: z.string().min(32),

  ADMIN_EMAIL: z.email(),
  ADMIN_USERNAME: z.string().min(3).default('admin'),
  ADMIN_PASSWORD: z.string().min(12),
});

export type Env = z.infer<typeof envSchema>;

/**
 * Valida el entorno. El mensaje de error solo nombra las variables y la regla
 * incumplida: nunca incluye valores (podrían ser secretos).
 */
export function validateEnv(raw: Record<string, unknown>): Env {
  const result = envSchema.safeParse(raw);
  if (!result.success) {
    const problems = result.error.issues
      .map((i) => `${i.path.join('.')}: ${i.code}`)
      .join(', ');
    throw new Error(`Configuración de entorno inválida → ${problems}`);
  }
  return result.data;
}
