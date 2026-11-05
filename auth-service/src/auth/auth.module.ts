import { readFileSync } from 'node:fs';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import type { Env } from '../config/env.schema.js';
import { RevokedToken } from '../database/entities/revoked-token.entity.js';
import { User } from '../database/entities/user.entity.js';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { AuthorizationService } from './authorization.service.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { PermissionsGuard } from './guards/permissions.guard.js';
import { TokenService } from './token.service.js';

@Module({
  imports: [TypeOrmModule.forFeature([User, RevokedToken])],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthorizationService,
    JwtAuthGuard,
    PermissionsGuard,
    {
      // Las claves se leen una vez al arrancar; si faltan o no son RSA, AUTH no arranca.
      provide: TokenService,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) =>
        new TokenService({
          privateKeyPem: readFileSync(
            config.get('JWT_PRIVATE_KEY_PATH', { infer: true }),
            'utf8',
          ),
          publicKeyPem: readFileSync(
            config.get('JWT_PUBLIC_KEY_PATH', { infer: true }),
            'utf8',
          ),
          issuer: config.get('JWT_ISSUER', { infer: true }),
          audience: config.get('JWT_AUDIENCE', { infer: true }),
          ttlSeconds: config.get('JWT_TTL_SECONDS', { infer: true }),
        }),
    },
  ],
  exports: [
    TokenService,
    AuthorizationService,
    JwtAuthGuard,
    PermissionsGuard,
    TypeOrmModule,
  ],
})
export class AuthModule {}
