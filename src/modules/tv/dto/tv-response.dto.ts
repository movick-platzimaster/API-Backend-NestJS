import { PageResultDto } from 'src/utils/page-result.dto';
import { ApiProperty } from '@nestjs/swagger';
import { TvReadDto } from './tv-read.dto';

export class TvResponseDto extends PageResultDto {
  @ApiProperty({ type: TvReadDto, isArray: true })
  readonly results: TvReadDto[];
}
