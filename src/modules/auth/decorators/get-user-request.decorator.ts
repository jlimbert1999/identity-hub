import {
  ExecutionContext,
  createParamDecorator,
  InternalServerErrorException,
} from '@nestjs/common';
import type { Request } from 'express';
import { User } from 'src/modules/users/entities';

export const GetUserRequest = createParamDecorator(
  (propertiePath: keyof User, ctx: ExecutionContext) => {
    const req: Request = ctx.switchToHttp().getRequest();
    const user = req['user'] as User | undefined;
    if (!user) {
      console.log('User not fount in request');
      throw new InternalServerErrorException('User not found in request');
    }
    return propertiePath ? user[propertiePath] : user;
  },
);
