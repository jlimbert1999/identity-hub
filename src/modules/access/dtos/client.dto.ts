import { PartialType } from '@nestjs/mapped-types';
import { IsArray, IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateApplicationDto {
  @IsString()
  @IsNotEmpty()
  clientId: string;

  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsNotEmpty()
  launchUrl: string;

  @IsString()
  @IsNotEmpty()
  defaultRole: string;

  @IsBoolean()
  isConfidential: boolean;

  @IsString({ each: true })
  @IsArray()
  redirectUris: string[];

  @IsBoolean()
  isActive: boolean;
}

export class UpdateClientDto extends PartialType(CreateApplicationDto) {}
