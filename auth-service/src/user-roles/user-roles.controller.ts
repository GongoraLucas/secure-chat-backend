import {
  Body,
  Controller,
  Delete,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { AuthenticatedRequest } from '../auth/auth-user.js';
import { RequirePermission } from '../auth/decorators/require-permission.decorator.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { PermissionsGuard } from '../auth/guards/permissions.guard.js';
import { AssignRoleDto } from './dto/assign-role.dto.js';
import { UserRolesService } from './user-roles.service.js';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AssignmentResponse, ErrorResponse } from '../common/swagger-models.js';

@ApiTags('user-roles')
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
@Controller('api/user-roles')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@RequirePermission('user_roles.manage')
export class UserRolesController {
  constructor(private readonly userRoles: UserRolesService) {}

  @Post()
  @ApiOperation({ summary: 'Asigna un rol a un usuario' })
  @ApiCreatedResponse({ type: AssignmentResponse })
  @ApiResponse({
    status: 400,
    description: 'Cuerpo inválido',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 404,
    description: 'Usuario o rol no existe',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 409,
    description: 'Asignación duplicada',
    type: ErrorResponse,
  })
  assign(@Body() dto: AssignRoleDto, @Req() req: AuthenticatedRequest) {
    return this.userRoles.assign(dto.user_id, dto.role_id, req.user.id);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Revoca una asignación' })
  @ApiNoContentResponse({ description: 'Asignación eliminada' })
  @ApiResponse({ status: 400, description: 'id inválido', type: ErrorResponse })
  @ApiResponse({
    status: 404,
    description: 'Asignación no encontrada',
    type: ErrorResponse,
  })
  @HttpCode(204)
  revoke(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: AuthenticatedRequest,
  ) {
    return this.userRoles.revoke(id, req.user.id);
  }
}
