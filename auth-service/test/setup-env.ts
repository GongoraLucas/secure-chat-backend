// Entorno mínimo válido para e2e. Se carga antes de importar AppModule
// (ConfigModule.forRoot valida al evaluarse el módulo).
// BD: contenedor desechable de ../scripts/test-db.sh (127.0.0.1:5433).
Object.assign(process.env, {
  NODE_ENV: 'test',
  DB_HOST: '127.0.0.1',
  DB_PORT: '5433',
  DB_USER: 'auth',
  DB_NAME: 'auth_test',
  DB_PASSWORD: 'e2e-db-pass',
  JWT_PRIVATE_KEY_PATH: '../keys/private.pem',
  JWT_PUBLIC_KEY_PATH: '../keys/public.pem',
  JWT_ISSUER: 'auth-service',
  JWT_AUDIENCE: 'secure-chat',
  SERVICE_TOKEN: 'e'.repeat(32),
  ADMIN_EMAIL: 'admin@example.com',
  ADMIN_PASSWORD: 'Admin-Pass-1234',
});
