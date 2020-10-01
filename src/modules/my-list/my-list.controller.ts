import {
  Controller,
  Post,
  Delete,
  Body,
  Param,
  Req,
  UseGuards,
  Get,
} from '@nestjs/common';
import { MyListService } from './my-list.service';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiOperation, ApiOkResponse } from '@nestjs/swagger';

@ApiTags('My list of movies and series')
@Controller('my-lists')
export class MyListController {
  constructor(private readonly _myListService: MyListService) {}

  @Get()
  @ApiOperation({ summary: 'Retrieves my movies and series' })
  @ApiOkResponse({
    description: 'An object with my series and movies',
  })
  @UseGuards(AuthGuard('jwt'))
  findAll(@Req() req) {
    return this._myListService.findAll(req.user.email);
  }
}
