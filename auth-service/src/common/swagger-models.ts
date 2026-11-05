import { ApiProperty } from '@nestjs/swagger';

/** Modelos de respuesta solo para OpenAPI (§11). Los servicios devuelven interfaces. */
const STATUS = ['active', 'inactive'];

export class ErrorResponse {
  @ApiProperty({ example: 401 })
  statusCode: number;

  @ApiProperty({ example: 'Unauthorized' })
  message: string;
}

export class LoginResponse {
  @ApiProperty({ description: 'JWT RS256 (exp ≤ 15 min)' })
  access_token: string;

  @ApiProperty({ enum: ['Bearer'] })
  token_type: string;

  @ApiProperty({ example: 900, description: 'Segundos hasta la expiración' })
  expires_in: number;
}

export class ProfileResponse {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty() username: string;
  @ApiProperty() email: string;
  @ApiProperty({ enum: STATUS }) status: string;
  @ApiProperty({ type: [String], example: ['ANALYST'] }) roles: string[];
}

export class UserRoleRef {
  @ApiProperty({ format: 'uuid' }) assignment_id: string;
  @ApiProperty({ format: 'uuid' }) role_id: string;
  @ApiProperty() name: string;
}

export class UserResponse {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty() username: string;
  @ApiProperty() email: string;
  @ApiProperty({ enum: STATUS }) status: string;
  @ApiProperty({ format: 'date-time' }) created_at: string;
  @ApiProperty({ format: 'date-time' }) updated_at: string;
}

export class UserWithRolesResponse extends UserResponse {
  @ApiProperty({ type: [UserRoleRef] }) roles: UserRoleRef[];
}

export class RoleResponse {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ example: 'ANALYST' }) name: string;
  @ApiProperty({ nullable: true, type: String }) description: string | null;
  @ApiProperty({ enum: STATUS }) status: string;
}

export class AssignmentResponse {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) user_id: string;
  @ApiProperty({ format: 'uuid' }) role_id: string;
  @ApiProperty({ format: 'date-time' }) assigned_at: string;
}

export class AuthorizationCheckResponse {
  @ApiProperty({ nullable: true, type: String, format: 'uuid' })
  subject_id: string | null;

  @ApiProperty({ example: 'steganography.analyze' }) action: string;
  @ApiProperty() allowed: boolean;

  @ApiProperty({
    enum: [
      'active_role_grants_permission',
      'no_active_role_grants_permission',
      'user_inactive',
      'token_revoked',
      'invalid_subject_token',
      'unknown_action',
    ],
  })
  reason: string;

  @ApiProperty({
    description: 'true solo en steganography.results.read con results.read_any',
  })
  can_read_any: boolean;
}

export class HealthResponse {
  @ApiProperty({ example: 'ok' }) status: string;
}
