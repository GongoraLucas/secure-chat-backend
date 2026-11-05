import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { configureApp } from './common/app-setup.js';
import type { Env } from './config/env.schema.js';
import { setupSwagger } from './common/swagger.js';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  configureApp(app);
  setupSwagger(app);
  app.enableShutdownHooks();
  const config = app.get<ConfigService<Env, true>>(ConfigService);
  await app.listen(config.get('PORT', { infer: true }), '0.0.0.0');
}

bootstrap().catch((err: unknown) => {
  // Solo el mensaje: sin valores de configuración.
  const msg = err instanceof Error ? err.message : 'error desconocido';
  new Logger('Bootstrap').error(`AUTH no pudo arrancar: ${msg}`);
  process.exit(1);
});
