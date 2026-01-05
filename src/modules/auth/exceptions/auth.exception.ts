import { BadRequestException } from '@nestjs/common';

export enum AuthErrorCode {
  INVALID_CREDENTIALS = 'invalid_credentials',
  USER_DISABLED = 'user_disabled',
  NOT_APPLICATION_ACCESS = 'not_application_access',
}

export class AuthException extends BadRequestException {
  constructor(public readonly code: AuthErrorCode) {
    super(code);
  }
}
