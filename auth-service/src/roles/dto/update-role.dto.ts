import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, Length } from 'class-validator';
import type { Status } from '../../database/entities/status.js';

/** §11: `{description?, status?}` (el nombre no se edita). */
export class UpdateRoleDto {
  @IsOptional()
  @IsString()
  @Length(0, 500)
  @ApiPropertyOptional()
  description?: string;

  @IsOptional()
  @IsIn(['active', 'inactive'])
  @ApiPropertyOptional()
  status?: Status;
}
