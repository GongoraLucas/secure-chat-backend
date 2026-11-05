import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from '../auth/auth.module.js';
import { Role } from '../database/entities/role.entity.js';
import { RolesController } from './roles.controller.js';
import { RolesService } from './roles.service.js';

@Module({
  imports: [AuthModule, TypeOrmModule.forFeature([Role])],
  controllers: [RolesController],
  providers: [RolesService],
})
export class RolesModule {}
