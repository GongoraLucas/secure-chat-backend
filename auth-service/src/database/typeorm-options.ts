import type { DataSourceOptions } from 'typeorm';
import type { Env } from '../config/env.schema.js';
import { ENTITIES } from './entities/index.js';
import { MIGRATIONS } from './migrations/index.js';

/** Única fuente de opciones de BD: la usan AppModule, el CLI de migraciones y el seed. */
export type DbEnv = Pick<
  Env,
  'DB_HOST' | 'DB_PORT' | 'DB_USER' | 'DB_PASSWORD' | 'DB_NAME'
>;

export function buildDataSourceOptions(env: DbEnv): DataSourceOptions {
  return {
    type: 'postgres',
    host: env.DB_HOST,
    port: env.DB_PORT,
    username: env.DB_USER,
    password: env.DB_PASSWORD,
    database: env.DB_NAME,
    entities: ENTITIES,
    migrations: MIGRATIONS,
    synchronize: false,
    migrationsRun: false,
    logging: ['error'],
  };
}
