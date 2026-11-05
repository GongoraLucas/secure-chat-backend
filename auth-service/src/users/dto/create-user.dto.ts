import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Length, Matches } from 'class-validator';

/** §11: `{username, email, password}`; contraseña mínima de 12 caracteres (máx. 128 para no hashear entradas enormes). */
export class CreateUserDto {
  @IsString()
  @Matches(/^[A-Za-z0-9_.-]+$/)
  @Length(3, 50)
  @ApiProperty()
  username: string;

  @IsEmail()
  @Length(3, 254)
  @ApiProperty()
  email: string;

  @IsString()
  @Length(12, 128)
  @ApiProperty()
  password: string;
}
