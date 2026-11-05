import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from '../auth/auth.module.js';
import { Role } from '../database/entities/role.entity.js';
import { UserRole } from '../database/entities/user-role.entity.js';
import { User } from '../database/entities/user.entity.js';
import { UserRolesController } from './user-roles.controller.js';
import { UserRolesService } from './user-roles.service.js';

@Module({
  imports: [AuthModule, TypeOrmModule.forFeature([UserRole, User, Role])],
  controllers: [UserRolesController],
  providers: [UserRolesService],
})
export class UserRolesModule {}
