import { Type } from 'class-transformer';
import { Min, Max, IsInt, IsString, IsNotEmpty, IsOptional, IsPositive } from 'class-validator';

export class PaginationParamsDto {
  @Type(() => Number)
  @IsInt()
  @IsPositive()
  @Min(1)
  @Max(50)
  @IsOptional()
  limit: number = 10;

  @Type(() => Number)
  @IsInt()
  @Min(0)
  @IsOptional()
  offset: number = 0;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  term?: string;
}
