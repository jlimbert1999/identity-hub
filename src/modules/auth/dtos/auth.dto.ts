import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class AuthDto {
  @IsNotEmpty()
  login: string;

  @IsNotEmpty()
  password: string;
}

export class AuthorizeDto {
  @IsString()
  clientId: string;

  @IsString()
  redirectUri: string;

  @IsString()
  @IsOptional()
  state?: string;
}

export class ExchangeCodeDto {
  @IsString()
  code: string;

  @IsString()
  client_id: string;
}

export class AuthorizeDtoGrouped {
  @IsString()
  login: string;

  @IsString()
  password: string;

  @IsString()
  clientId: string;

  @IsString()
  redirectUri: string;

  @IsOptional()
  @IsString()
  state?: string;
}

export class RefreshTokenDto {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
