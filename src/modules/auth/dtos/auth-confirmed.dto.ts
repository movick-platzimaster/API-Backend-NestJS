import { IsBoolean, IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AuthConfirmedDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  token: string
  @ApiProperty()
  @IsEmail()
  @IsNotEmpty()
  email: string

  @ApiProperty()
  @IsBoolean()
  confirmed: boolean
}
