import { Type } from 'class-transformer';
import {
  ArrayMinSize,
  IsArray,
  IsNotEmpty,
  IsNumber,
  IsString,
} from 'class-validator';

export class CreateAssigmentDto {
  @IsString()
  @IsNotEmpty()
  userId: string;

  @IsArray()
  @Type(() => Number)
  @IsNumber({}, { each: true })
  @ArrayMinSize(2)
  clientIds: number[];
}
