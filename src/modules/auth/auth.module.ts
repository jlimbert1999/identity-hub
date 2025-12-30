import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

import { AuthController, OauthController } from './controllers';
import { AuthService, SSOAuthService } from './services';
import { UsersModule } from '../users/users.module';
import { EnvironmentVariables } from 'src/config';

@Module({
  controllers: [AuthController, OauthController],
  providers: [AuthService, SSOAuthService],
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService<EnvironmentVariables>) => ({
        secret: configService.getOrThrow('JWT_KEY'),
        signOptions: { expiresIn: '8h' },
      }),
      inject: [ConfigService],
    }),
    UsersModule,
  ],
  exports: [AuthService, SSOAuthService],
})
export class AuthModule {}
