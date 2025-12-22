import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.enableCors({
    // Permitir acceso desde el frontend de Angular (4200)
    origin: 'http://localhost:4300',

    // VITAL: Si el frontend usa withCredentials, este backend DEBE responder con 'true'
    credentials: true,

    // Permitir los métodos necesarios (POST, GET, etc.)
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    // ... otros headers si son necesarios
  });
  app.use(cookieParser());
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
