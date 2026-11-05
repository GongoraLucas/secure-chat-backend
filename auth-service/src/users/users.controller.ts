import {
  Body,
  Controller,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { RequirePermission } from '../auth/decorators/require-permission.decorator.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { PermissionsGuard } from '../auth/guards/permissions.guard.js';
import { CreateUserDto } from './dto/create-user.dto.js';
import { UpdateUserDto } from './dto/update-user.dto.js';
import { UsersService } from './users.service.js';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import {
  ErrorResponse,
  UserResponse,
  UserWithRolesResponse,
} from '../common/swagger-models.js';

@ApiTags('users')
@ApiBearerAuth()
@ApiResponse({
  status: 401,
  description: 'Token ausente, inválido o revocado',
  type: ErrorResponse,
})
@ApiResponse({
  status: 403,
  description: 'Sin permiso (solo ADMIN)',
  type: ErrorResponse,
})
@Controller('api/users')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@RequirePermission('users.manage')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @ApiOperation({ summary: 'Lista usuarios con sus roles' })
  @ApiOkResponse({ type: [UserWithRolesResponse] })
  list() {
    return this.users.list();
  }

  @Post()
  @ApiOperation({ summary: 'Crea usuario (password ≥ 12)' })
  @ApiCreatedResponse({ type: UserResponse })
  @ApiResponse({
    status: 400,
    description: 'Cuerpo inválido',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 409,
    description: 'username o email duplicado',
    type: ErrorResponse,
  })
  create(@Body() dto: CreateUserDto) {
    return this.users.create(dto);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Actualiza email, status o password' })
  @ApiOkResponse({ type: UserResponse })
  @ApiResponse({
    status: 400,
    description: 'Cuerpo o id inválido',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 404,
    description: 'Usuario no encontrado',
    type: ErrorResponse,
  })
  update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateUserDto) {
    return this.users.update(id, dto);
  }
}
