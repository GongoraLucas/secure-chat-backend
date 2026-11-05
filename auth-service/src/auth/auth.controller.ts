import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { Request } from 'express';
import type { AuthenticatedRequest } from './auth-user.js';
import { AuthService, type LoginResult, type Profile } from './auth.service.js';
import { RequirePermission } from './decorators/require-permission.decorator.js';
import { LoginDto } from './dto/login.dto.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { LoginRateLimitGuard } from './guards/login-rate-limit.guard.js';
import { PermissionsGuard } from './guards/permissions.guard.js';
import {
  ApiBearerAuth,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import {
  ErrorResponse,
  LoginResponse,
  ProfileResponse,
} from '../common/swagger-models.js';

@ApiTags('auth')
@Controller('api/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  /** Rate limit por IP solo en esta ruta. */
  @Post('login')
  @ApiOperation({ summary: 'Login (público, rate limit por IP)' })
  @ApiOkResponse({ type: LoginResponse })
  @ApiResponse({
    status: 400,
    description: 'Cuerpo inválido',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 401,
    description: 'Credenciales inválidas (mensaje genérico)',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 429,
    description: 'Demasiados intentos',
    type: ErrorResponse,
  })
  @HttpCode(200)
  @UseGuards(LoginRateLimitGuard)
  login(@Body() dto: LoginDto, @Req() req: Request): Promise<LoginResult> {
    return this.auth.login(dto.username, dto.password, req.ip);
  }

  /** Revoca el jti del token presentado; JwtAuthGuard lo rechaza a partir de aquí. */
  @Post('logout')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Revoca el jti del token presentado' })
  @ApiNoContentResponse({ description: 'jti revocado' })
  @ApiResponse({
    status: 401,
    description: 'Token ausente, inválido o revocado',
    type: ErrorResponse,
  })
  @ApiResponse({ status: 403, description: 'Sin permiso', type: ErrorResponse })
  @HttpCode(204)
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermission('profile.read')
  logout(@Req() req: AuthenticatedRequest): Promise<void> {
    return this.auth.logout(req.user);
  }

  @Get('profile')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Perfil del usuario autenticado' })
  @ApiOkResponse({ type: ProfileResponse })
  @ApiResponse({
    status: 401,
    description: 'Token ausente, inválido o revocado',
    type: ErrorResponse,
  })
  @ApiResponse({ status: 403, description: 'Sin permiso', type: ErrorResponse })
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermission('profile.read')
  profile(@Req() req: AuthenticatedRequest): Promise<Profile> {
    return this.auth.profile(req.user.id);
  }
}
