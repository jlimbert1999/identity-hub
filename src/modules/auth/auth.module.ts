import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from '../users/users.module';
import { EnvironmentVariables } from 'src/config';
import { OauthController } from './controllers/oauth.controller';
import { AuthService, SSOAuthService } from './services';
import { TypeOrmModule } from '@nestjs/typeorm';

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
