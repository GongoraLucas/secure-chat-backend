import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length } from 'class-validator';

/** §11: `{username, password}`. Longitudes máximas para no hashear entradas enormes. */
export class LoginDto {
  @IsString()
  @Length(1, 50)
  @ApiProperty()
  username: string;

  @IsString()
  @Length(1, 128)
  @ApiProperty()
  password: string;
}
