import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module.js';
import { type Env, validateEnv } from './config/env.schema.js';
import { buildDataSourceOptions } from './database/typeorm-options.js';
import { HealthController } from './health/health.controller.js';
import { InternalModule } from './internal/internal.module.js';
import { RolesModule } from './roles/roles.module.js';
import { UserRolesModule } from './user-roles/user-roles.module.js';
import { UsersModule } from './users/users.module.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      // En Docker las variables llegan por env_file/environment; no hay .env en la imagen.
      ignoreEnvFile: process.env.NODE_ENV === 'production',
      validate: validateEnv,
    }),
    // synchronize:false y sin migrationsRun: el esquema solo cambia con `npm run migration:run`.
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) => ({
        ...buildDataSourceOptions({
          DB_HOST: config.get('DB_HOST', { infer: true }),
          DB_PORT: config.get('DB_PORT', { infer: true }),
          DB_USER: config.get('DB_USER', { infer: true }),
          DB_PASSWORD: config.get('DB_PASSWORD', { infer: true }),
          DB_NAME: config.get('DB_NAME', { infer: true }),
        }),
        retryAttempts: 5,
      }),
    }),
    AuthModule,
    UsersModule,
    RolesModule,
    UserRolesModule,
    InternalModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
