import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsIn, IsOptional, IsString, Length } from 'class-validator';
import type { Status } from '../../database/entities/status.js';

/** §11: `{email?, status?, password?}`. */
export class UpdateUserDto {
  @IsOptional()
  @IsEmail()
  @Length(3, 254)
  @ApiPropertyOptional()
  email?: string;

  @IsOptional()
  @IsIn(['active', 'inactive'])
  @ApiPropertyOptional()
  status?: Status;

  @IsOptional()
  @IsString()
  @Length(12, 128)
  @ApiPropertyOptional()
  password?: string;
}
