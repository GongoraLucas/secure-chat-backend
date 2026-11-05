import { DataSource } from 'typeorm';
import { validateEnv } from '../config/env.schema.js';
import { buildDataSourceOptions } from './typeorm-options.js';

/** DataSource para el CLI de TypeORM: `npm run migration:run`. */
export default new DataSource(buildDataSourceOptions(validateEnv(process.env)));
