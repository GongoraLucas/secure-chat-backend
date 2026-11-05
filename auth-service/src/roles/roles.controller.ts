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
import { CreateRoleDto } from './dto/create-role.dto.js';
import { UpdateRoleDto } from './dto/update-role.dto.js';
import { RolesService } from './roles.service.js';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ErrorResponse, RoleResponse } from '../common/swagger-models.js';

@ApiTags('roles')
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
@Controller('api/roles')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@RequirePermission('roles.manage')
export class RolesController {
  constructor(private readonly roles: RolesService) {}

  @Get()
  @ApiOperation({ summary: 'Lista roles' })
  @ApiOkResponse({ type: [RoleResponse] })
  list() {
    return this.roles.list();
  }

  @Post()
  @ApiOperation({ summary: 'Crea rol' })
  @ApiCreatedResponse({ type: RoleResponse })
  @ApiResponse({
    status: 400,
    description: 'Cuerpo inválido',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 409,
    description: 'Nombre de rol duplicado',
    type: ErrorResponse,
  })
  create(@Body() dto: CreateRoleDto) {
    return this.roles.create(dto);
  }

  @Patch(':id')
  @ApiOperation({
    summary: 'Actualiza description o status (el nombre no se edita)',
  })
  @ApiOkResponse({ type: RoleResponse })
  @ApiResponse({
    status: 400,
    description: 'Cuerpo o id inválido',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 404,
    description: 'Rol no encontrado',
    type: ErrorResponse,
  })
  update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateRoleDto) {
    return this.roles.update(id, dto);
  }
}
