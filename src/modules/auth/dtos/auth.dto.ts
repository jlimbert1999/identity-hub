import { Expose } from 'class-transformer';
import { Equals, IsEnum, IsIn, IsNotEmpty, IsOptional, IsString, IsUrl, IsUUID } from 'class-validator';


export class AuthorizeParamsDto {
  @IsString()
  @IsNotEmpty()
  @Expose({ name: 'client_id' })
  clientId: string;

  @IsString()
  @IsNotEmpty()
  @Expose({ name: 'redirect_uri' })
  redirectUri: string;

  @IsString()
  @Equals('code', { message: 'response type must be "code"' })
  responseType?: string;

  @IsString()
  @IsNotEmpty()
  @IsOptional()
  scope?: string;

  @IsString()
  @IsNotEmpty()
  @IsOptional()
  state?: string;
}
export class LoginDto {
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
  @Expose({ name: 'auth_request_id' })
  authRequestId?: string;
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
