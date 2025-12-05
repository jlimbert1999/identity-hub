import { IsNotEmpty, IsString } from 'class-validator';

export class DirectLoginDto {
  @IsNotEmpty()
  @IsString()
  login: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsNotEmpty()
  @IsString()
  clientKey: string;
}
