import { HttpModule, Module } from '@nestjs/common';
import { CategoriesController } from './categories.controller';
import { CategoriesService } from './categories.service';
import { MongooseModule } from '@nestjs/mongoose';
import { CategorySchema } from './schemas/category.schema';
import { ConfigModule } from '../../config/config.module';
import { UtilsModule } from '../../utils/utils.module';

@Module({
  imports: [ConfigModule, HttpModule, MongooseModule.forFeature([{ name: 'category', schema: CategorySchema }]),
    UtilsModule
  ],
  controllers: [CategoriesController],
  providers: [CategoriesService],
})
export class CategoriesModule {
}