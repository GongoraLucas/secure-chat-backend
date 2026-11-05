import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

/** Swagger UI en /api/docs (JSON en /api/docs-json). Se llama desde main.ts y los tests. */
export function setupSwagger(app: INestApplication): void {
  const config = new DocumentBuilder()
    .setTitle('AUTH service')
    .setDescription(
      'Usuarios, roles N:M, JWT RS256 y autorización RBAC desde BD. Errores: { statusCode, message }.',
    )
    .setVersion('1.0')
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' })
    .addApiKey(
      { type: 'apiKey', in: 'header', name: 'X-Service-Token' },
      'service-token',
    )
    .build();
  SwaggerModule.setup(
    'api/docs',
    app,
    SwaggerModule.createDocument(app, config),
  );
}
