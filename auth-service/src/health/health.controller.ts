import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { HealthResponse } from '../common/swagger-models.js';

@ApiTags('health')
@Controller('health')
export class HealthController {
  @Get()
  @ApiOkResponse({ type: HealthResponse })
  check(): { status: 'ok' } {
    return { status: 'ok' };
  }
}
