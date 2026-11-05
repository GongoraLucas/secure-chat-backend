import { type INestApplication, ValidationPipe } from '@nestjs/common';
import { HttpErrorFilter } from './filters/http-exception.filter.js';

/** Configuración común a main.ts y los e2e: así los tests prueban la misma app. */
export function configureApp(app: INestApplication): void {
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      forbidUnknownValues: true,
    }),
  );
  app.useGlobalFilters(new HttpErrorFilter());
}
