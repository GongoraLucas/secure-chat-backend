import { Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { validateEnv } from '../../config/env.schema.js';
import { buildDataSourceOptions } from '../typeorm-options.js';
import { runSeed } from './seed.js';

/** CLI: `npm run seed` (tras `npm run migration:run`). */
const logger = new Logger('Seed');
const env = validateEnv(process.env);
const ds = new DataSource(buildDataSourceOptions(env));

try {
  await ds.initialize();
  await runSeed(ds, env);
  logger.log('seed aplicado (roles, permisos y admin inicial)');
} catch (err: unknown) {
  logger.error(
    `seed fallido: ${err instanceof Error ? err.message : 'error desconocido'}`,
  );
  process.exitCode = 1;
} finally {
  if (ds.isInitialized) await ds.destroy();
}
