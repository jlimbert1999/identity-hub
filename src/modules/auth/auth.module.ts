import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

import { OAuthController, AuthController } from './controllers';
import { AuthService, OAuthService } from './services';
import { UsersModule } from '../users/users.module';
import { EnvironmentVariables } from 'src/config';

@Module({
  controllers: [OAuthController, AuthController],
  providers: [AuthService, OAuthService],
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
  exports: [AuthService, OAuthService],
})
export class AuthModule {}
