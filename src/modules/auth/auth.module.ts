import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from '../users/users.module';
import { EnvironmentVariables } from 'src/config';
import { OauthController } from './controllers/oauth.controller';

@Module({
  controllers: [AuthController, OauthController],
  providers: [AuthService],
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
})
export class AuthModule {}
