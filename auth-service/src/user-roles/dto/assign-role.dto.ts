import { ApiProperty } from '@nestjs/swagger';
import { IsUUID } from 'class-validator';

/** §11: `{user_id, role_id}`. */
export class AssignRoleDto {
  @IsUUID()
  @ApiProperty()
  user_id: string;

  @IsUUID()
  @ApiProperty()
  role_id: string;
}
