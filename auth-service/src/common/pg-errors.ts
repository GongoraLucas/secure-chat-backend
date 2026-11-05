/** Violación de UNIQUE en Postgres (SQLSTATE 23505), tal como la expone TypeORM/pg. */
export function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; driverError?: { code?: string } };
  return e?.code === '23505' || e?.driverError?.code === '23505';
}
