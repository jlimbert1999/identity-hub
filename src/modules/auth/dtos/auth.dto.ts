import {
  Equals,
  IsNotEmpty,
  IsOptional,
  IsString,
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

export class LoginParamsDto {
  @IsOptional()
  @IsUUID()
  auth_request_id?: string;
}

export class AuthorizeDto {
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
  scope: string;
}
export class ExchangeCodeDto {
  @IsString()
  code: string;

  @IsString()
  client_id: string;
}

export class AuthorizeDtoGrouped {
  // @IsString()
  // login: string;

  // @IsString()
  // password: string;

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
