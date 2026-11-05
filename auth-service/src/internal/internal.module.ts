import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { AuthorizationCheckService } from './authorization-check.service.js';
import { AuthorizationController } from './authorization.controller.js';
import { ServiceTokenGuard } from './service-token.guard.js';

@Module({
  imports: [AuthModule],
  controllers: [AuthorizationController],
  providers: [AuthorizationCheckService, ServiceTokenGuard],
})
export class InternalModule {}
