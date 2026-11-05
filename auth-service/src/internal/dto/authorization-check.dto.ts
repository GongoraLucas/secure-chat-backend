import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength } from 'class-validator';

/** Cuerpo de §6. El cliente final nunca llega aquí: solo STEGO con X-Service-Token. */
export class AuthorizationCheckDto {
  @IsString()
  @MaxLength(8192)
  @ApiProperty()
  subject_token: string;

  @IsString()
  @MaxLength(100)
  @ApiProperty()
  action: string;

  /** STEGO aplica la propiedad del recurso; AUTH no lo usa. */
  @IsOptional()
  @IsString()
  @MaxLength(64)
  @ApiPropertyOptional()
  resource_id?: string | null;
}
