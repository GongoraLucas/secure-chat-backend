import { Permission } from './permission.entity.js';
import { RevokedToken } from './revoked-token.entity.js';
import { RolePermission } from './role-permission.entity.js';
import { Role } from './role.entity.js';
import { UserRole } from './user-role.entity.js';
import { User } from './user.entity.js';

export { Permission, RevokedToken, Role, RolePermission, User, UserRole };

export const ENTITIES = [
  User,
  Role,
  UserRole,
  Permission,
  RolePermission,
  RevokedToken,
];
