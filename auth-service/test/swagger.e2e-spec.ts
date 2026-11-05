import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types.js';
import { AppModule } from '../src/app.module.js';
import { setupSwagger } from '../src/common/swagger.js';

describe('OpenAPI /api/docs (e2e)', () => {
  let app: INestApplication<App>;
  let doc: {
    paths: Record<
      string,
      Record<
        string,
        { security?: object[]; responses: Record<string, unknown> }
      >
    >;
    components: { securitySchemes: Record<string, unknown> };
  };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication();
    setupSwagger(app);
    await app.init();
    doc = (await request(app.getHttpServer()).get('/api/docs-json').expect(200))
      .body;
  });

  afterAll(async () => {
    await app?.close();
  });

  it('documenta todas las rutas de §2 con sus métodos', () => {
    const expected: [string, string][] = [
      ['/api/auth/login', 'post'],
      ['/api/auth/profile', 'get'],
      ['/api/auth/logout', 'post'],
      ['/api/users', 'get'],
      ['/api/users', 'post'],
      ['/api/users/{id}', 'patch'],
      ['/api/roles', 'get'],
      ['/api/roles', 'post'],
      ['/api/roles/{id}', 'patch'],
      ['/api/user-roles', 'post'],
      ['/api/user-roles/{id}', 'delete'],
      ['/internal/authorization/check', 'post'],
      ['/health', 'get'],
    ];
    for (const [path, method] of expected) {
      expect(doc.paths[path]?.[method]).toBeDefined();
    }
  });

  it('declara los esquemas bearer y X-Service-Token', () => {
    expect(doc.components.securitySchemes).toHaveProperty('bearer');
    expect(doc.components.securitySchemes).toHaveProperty('service-token');
    expect(doc.paths['/api/users'].get.security).toEqual([{ bearer: [] }]);
    expect(doc.paths['/internal/authorization/check'].post.security).toEqual([
      { 'service-token': [] },
    ]);
  });

  it('documenta los códigos de error de §11', () => {
    expect(doc.paths['/api/auth/login'].post.responses).toHaveProperty('429');
    expect(doc.paths['/api/users'].post.responses).toHaveProperty('409');
    expect(doc.paths['/api/users'].get.responses).toHaveProperty('403');
    expect(
      doc.paths['/internal/authorization/check'].post.responses,
    ).toHaveProperty('401');
  });
});
