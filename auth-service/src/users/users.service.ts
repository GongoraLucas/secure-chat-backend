import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as argon2 from 'argon2';
import type { Repository } from 'typeorm';
import { isUniqueViolation } from '../common/pg-errors.js';
import type { Status } from '../database/entities/status.js';
import { User } from '../database/entities/user.entity.js';
import type { CreateUserDto } from './dto/create-user.dto.js';
import type { UpdateUserDto } from './dto/update-user.dto.js';

export interface UserView {
  id: string;
  username: string;
  email: string;
  status: Status;
  created_at: Date;
  updated_at: Date;
}

export interface UserWithRoles extends UserView {
  roles: { assignment_id: string; role_id: string; name: string }[];
}

const toView = (u: User): UserView => ({
  id: u.id,
  username: u.username,
  email: u.email,
  status: u.status,
  created_at: u.createdAt,
  updated_at: u.updatedAt,
});

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
  ) {}

  async list(): Promise<UserWithRoles[]> {
    const users = await this.users.find({ order: { createdAt: 'ASC' } });
    const rows: {
      user_id: string;
      assignment_id: string;
      role_id: string;
      name: string;
    }[] = await this.users.query(
      `SELECT ur.user_id, ur.id AS assignment_id, r.id AS role_id, r.name
       FROM user_roles ur JOIN roles r ON r.id = ur.role_id
       ORDER BY r.name`,
    );
    return users.map((u) => ({
      ...toView(u),
      roles: rows
        .filter((r) => r.user_id === u.id)
        .map(({ assignment_id, role_id, name }) => ({
          assignment_id,
          role_id,
          name,
        })),
    }));
  }

  async create(dto: CreateUserDto): Promise<UserView> {
    const passwordHash = await argon2.hash(dto.password, {
      type: argon2.argon2id,
    });
    try {
      const saved = await this.users.save(
        this.users.create({
          username: dto.username,
          email: dto.email,
          passwordHash,
        }),
      );
      return toView(saved);
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new ConflictException('Usuario o email ya existe');
      }
      throw err;
    }
  }

  async update(id: string, dto: UpdateUserDto): Promise<UserView> {
    const user = await this.users.findOneBy({ id });
    if (!user) throw new NotFoundException('Usuario no encontrado');
    if (dto.email !== undefined) user.email = dto.email;
    if (dto.status !== undefined) user.status = dto.status;
    if (dto.password !== undefined) {
      user.passwordHash = await argon2.hash(dto.password, {
        type: argon2.argon2id,
      });
    }
    try {
      return toView(await this.users.save(user));
    } catch (err) {
      if (isUniqueViolation(err))
        throw new ConflictException('Email ya existe');
      throw err;
    }
  }
}
