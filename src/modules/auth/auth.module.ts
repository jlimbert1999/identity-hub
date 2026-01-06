import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { AuthService, OAuthService, TokenService } from './services';
import { OAuthController, AuthController } from './controllers';
import { UsersModule } from '../users/users.module';
import { EnvironmentVariables } from 'src/config';
import { AccessModule } from '../access/access.module';
import { SessionGuard } from './guards/session.guard';

@Module({
  controllers: [OAuthController, AuthController],
  providers: [
    AuthService,
    OAuthService,
    TokenService,
    {
      provide: APP_GUARD,
      useClass: SessionGuard,
    },
  ],
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService<EnvironmentVariables>) => ({
        privateKey: configService.get('JWT_PRIVATE_KEY'),
        publicKey: configService.get('JWT_PUBLIC_KEY'), // Ú
      }),
      inject: [ConfigService],
    }),
    UsersModule,
    AccessModule,
  ],
})
export class AuthModule {}
