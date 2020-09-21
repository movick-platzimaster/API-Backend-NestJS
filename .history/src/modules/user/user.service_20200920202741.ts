import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { UserCreateDto } from './dtos/user-create.dto';

@Injectable()
export class UserService {
  constructor(@InjectModel('user') private userModel: Model<User>) {}

  findAll(): Promise<User[]> {
    return this.userModel.find().exec();
  }

  findById(userId: string): Promise<User> {
    return this.userModel.findById(userId).exec();
  }

  create(userCreateDto: UserCreateDto): Promise<User> {
    const userCreated = new this.userModel(userCreateDto);
    return userCreated.save();
  }
}
