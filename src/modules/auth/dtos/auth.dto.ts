import {
  Equals,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  IsUUID,
} from 'class-validator';

export class AuthDto {
  @IsNotEmpty()
  login: string;

  @IsNotEmpty()
  password: string;

  @IsString()
  @IsOptional()
  redirectUrl?: string;
}

export class TokenRequestDto {
  @IsString()
  code: string;

  @IsString()
  client_id: string;

  @IsUrl()
  redirect_uri: string;
}

export class LoginParamsDto {
  @IsOptional()
  @IsUUID()
  auth_request_id?: string;
}

export class AuthorizeParamsDto {
  @IsString()
  @IsNotEmpty()
  client_id: string;

  @IsNotEmpty()
  redirect_uri: string;

  @IsString()
  @Equals('code', { message: 'response_type must be "code"' })
  response_type: string;

  @IsString()
  @IsNotEmpty()
  state: string;
}
export class ExchangeCodeDto {
  @IsString()
  code: string;

  @IsString()
  client_id: string;
}

export class RefreshTokenDto {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
