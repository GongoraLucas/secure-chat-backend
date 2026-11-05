import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type { Repository } from 'typeorm';
import { isUniqueViolation } from '../common/pg-errors.js';
import { Role } from '../database/entities/role.entity.js';
import { UserRole } from '../database/entities/user-role.entity.js';
import { User } from '../database/entities/user.entity.js';

export interface AssignmentView {
  id: string;
  user_id: string;
  role_id: string;
  assigned_at: Date;
}

@Injectable()
export class UserRolesService {
  private readonly logger = new Logger('UserRoles');

  constructor(
    @InjectRepository(UserRole)
    private readonly assignments: Repository<UserRole>,
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(Role) private readonly roles: Repository<Role>,
  ) {}

  async assign(
    userId: string,
    roleId: string,
    actorId: string,
  ): Promise<AssignmentView> {
    if (!(await this.users.existsBy({ id: userId }))) {
      throw new NotFoundException('Usuario no encontrado');
    }
    if (!(await this.roles.existsBy({ id: roleId }))) {
      throw new NotFoundException('Rol no encontrado');
    }
    try {
      const saved = await this.assignments.save(
        this.assignments.create({ userId, roleId }),
      );
      this.logger.log(
        `role_assigned actor_id=${actorId} user_id=${userId} role_id=${roleId}`,
      );
      return {
        id: saved.id,
        user_id: saved.userId,
        role_id: saved.roleId,
        assigned_at: saved.assignedAt,
      };
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new ConflictException('El usuario ya tiene ese rol');
      }
      throw err;
    }
  }

  async revoke(id: string, actorId: string): Promise<void> {
    const found = await this.assignments.findOneBy({ id });
    if (!found) throw new NotFoundException('Asignación no encontrada');
    await this.assignments.delete({ id });
    this.logger.log(
      `role_revoked actor_id=${actorId} user_id=${found.userId} role_id=${found.roleId}`,
    );
  }
}
