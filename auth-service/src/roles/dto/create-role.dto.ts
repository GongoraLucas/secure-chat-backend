import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, Length, Matches } from 'class-validator';

/** §11: `{name, description}`. */
export class CreateRoleDto {
  @IsString()
  @Matches(/^[A-Z][A-Z0-9_]*$/)
  @Length(2, 50)
  @ApiProperty()
  name: string;

  @IsOptional()
  @IsString()
  @Length(0, 500)
  @ApiPropertyOptional()
  description?: string;
}
