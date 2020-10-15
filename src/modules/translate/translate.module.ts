import { Module } from '@nestjs/common';
import { TranslateService } from './translate.service';
import { ConfigModule } from '../../config/config.module';

@Module({
  imports: [ConfigModule],
  providers: [TranslateService]
})
export class TranslateModule {}