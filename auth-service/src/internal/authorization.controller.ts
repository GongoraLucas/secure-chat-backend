import { Body, Controller, HttpCode, Post, UseGuards } from '@nestjs/common';
import {
  AuthorizationCheckService,
  type CheckResult,
} from './authorization-check.service.js';
import { AuthorizationCheckDto } from './dto/authorization-check.dto.js';
import { ServiceTokenGuard } from './service-token.guard.js';
import {
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  AuthorizationCheckResponse,
  ErrorResponse,
} from '../common/swagger-models.js';

/** Endpoint servicio a servicio (§6, §11). Denegar es 200 con allowed:false. */
@ApiTags('internal')
@ApiSecurity('service-token')
@Controller('internal/authorization')
@UseGuards(ServiceTokenGuard)
export class AuthorizationController {
  constructor(private readonly checker: AuthorizationCheckService) {}

  @Post('check')
  @ApiOperation({
    summary:
      'Decisión de autorización para STEGO (denegar es 200 con allowed:false)',
  })
  @ApiOkResponse({ type: AuthorizationCheckResponse })
  @ApiResponse({
    status: 400,
    description: 'Cuerpo inválido',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 401,
    description: 'X-Service-Token ausente o inválido',
    type: ErrorResponse,
  })
  @HttpCode(200)
  check(@Body() dto: AuthorizationCheckDto): Promise<CheckResult> {
    return this.checker.check(dto.subject_token, dto.action);
  }
}
