import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type { Repository } from 'typeorm';
import { isUniqueViolation } from '../common/pg-errors.js';
import { Role } from '../database/entities/role.entity.js';
import type { Status } from '../database/entities/status.js';
import type { CreateRoleDto } from './dto/create-role.dto.js';
import type { UpdateRoleDto } from './dto/update-role.dto.js';

export interface RoleView {
  id: string;
  name: string;
  description: string | null;
  status: Status;
}

const toView = (r: Role): RoleView => ({
  id: r.id,
  name: r.name,
  description: r.description,
  status: r.status,
});

@Injectable()
export class RolesService {
  constructor(
    @InjectRepository(Role) private readonly roles: Repository<Role>,
  ) {}

  async list(): Promise<RoleView[]> {
    return (await this.roles.find({ order: { name: 'ASC' } })).map(toView);
  }

  async create(dto: CreateRoleDto): Promise<RoleView> {
    try {
      const saved = await this.roles.save(
        this.roles.create({
          name: dto.name,
          description: dto.description ?? null,
        }),
      );
      return toView(saved);
    } catch (err) {
      if (isUniqueViolation(err))
        throw new ConflictException('El rol ya existe');
      throw err;
    }
  }

  async update(id: string, dto: UpdateRoleDto): Promise<RoleView> {
    const role = await this.roles.findOneBy({ id });
    if (!role) throw new NotFoundException('Rol no encontrado');
    if (dto.description !== undefined) role.description = dto.description;
    if (dto.status !== undefined) role.status = dto.status;
    return toView(await this.roles.save(role));
  }
}
