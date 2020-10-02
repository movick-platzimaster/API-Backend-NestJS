import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignChangeDto, SigninDto, SignupDto } from './dtos';
import { compare, genSalt, hash } from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../user/schemas/user.schema';
import { IJwtPayload } from './interfaces/jwt-payload.interface';
import { UtilService } from '../../util/util.service';
import { generatePin } from 'generate-pin';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigEnum } from '../../config/config.keys';
import { ConfigService } from '../../config/config.service';
import { generateVerificationCodeTemplate } from './templates/verificationCode-email-spanish';
import { PinConfirmationDto } from './dtos/pin-confirmation.dto';
import { AuthConfirmedDto } from './dtos/auth-confirmed.dto';
import { plainToClass } from 'class-transformer';
import { AuthResendCodeDto } from './dtos/auth-resend-code.dto';
import PasswordValidator = require('password-validator');
import sgMail = require('@sendgrid/mail');
import moment = require('moment');
import { generateVerificationCodeTemplateEnglish } from './templates/verificationCode-email-english';
import { SigninResponseDto } from './dtos/signin-response.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly _jwtService: JwtService,
    private readonly _utilService: UtilService,
    private readonly _configService: ConfigService,
    @InjectModel('user') private userModel: Model<User>,
  ) {}

  async signUp(signup: SignupDto): Promise<void> {
    const user = await this.userModel.findOne({ email: signup.email });
    if (!user) {
      console.log('Registrando ', signup);
      const isSecure = this.isValidPassword(signup.password);
      if (!isSecure) {
        throw new ConflictException('password_not_secure');
      }
      const salt = await genSalt(10);
      signup.password = await hash(signup.password, salt);
      const userCreated = new this.userModel(signup);
      // Generates a PIN to confirm the user later
      userCreated.pin = generatePin()[0];
      await userCreated.save();
      return;
    }
    throw new ConflictException('email_already_exists');
  }

  async signIn(signin: SigninDto): Promise<SigninResponseDto> {
    const { password } = signin;
    const user = await this.userModel.findOne({ email: signin.email });
    if (!user) throw new NotFoundException('invalid_credentials');
    const isMatch = await compare(password, user.password);
    console.log('Debo de autenticar?', isMatch);
    if (!isMatch) throw new UnauthorizedException('invalid_credentials');
    const token = await this.generateJwt(user)
    return plainToClass(SigninResponseDto, {
      accessToken: token,
      name: user.name,
      email: user.email,
    });
  }

  async signChange(signChange: SignChangeDto): Promise<boolean> {
    const user = await this.userModel.findOne({ email: signChange.email });
    if (!user) throw new NotFoundException('user_not_found');
    const isMatch = await compare(signChange.old, user.password);
    if (!isMatch) throw new UnauthorizedException('invalid_credentials');
    const isSecure = this.isValidPassword(signChange.new);
    if (!isSecure) {
      throw new ConflictException('password_not_secured');
    }
    const salt = await genSalt(10);
    user.password = await hash(signChange.new, salt);
    await user.save();
    return true;
  }

  private isValidPassword(password: string) {
    const schema = new PasswordValidator();
    schema
      .is()
      .min(10) // Minimum length 10
      .is()
      .max(20) // Maximum length 20
      .has()
      .uppercase() // Must have uppercase letters
      .has()
      .lowercase() // Must have lowercase letters
      .has()
      .digits() // Must have at least 2 digits
      .has()
      .symbols() // Must have symbols
      .has()
      .not()
      .spaces();
    const isSecure = schema.validate(password);
    if (!isSecure) {
      console.log(
        'The password has not ',
        schema.validate(password, { list: true }),
      );
    }
    return isSecure;
  }

  async confirm(pin: PinConfirmationDto): Promise<AuthConfirmedDto> {
    const user = await this.userModel.findOne({ email: pin.email });
    if (!user) {
      throw new BadRequestException('invalid_user')
    }

    if (user.confirmed) {
      const token = await this.generateJwt(user)
      return plainToClass(AuthConfirmedDto, {
        token,
        email: pin.email,
        confirmed: true,
      });
    }

    const pinMatched = user.pin === pin.pin;
    if (pinMatched) {
      user.confirmed = true;
      user.expirationDate = null;
      user.pin = null;
      await user.save();
      const token = await this.generateJwt(user)
      return plainToClass(AuthConfirmedDto, {
        token,
        email: pin.email,
        confirmed: true,
      });
    }
    throw new ConflictException('pin_not_match');
  }

  async generateJwt(user: User): Promise<string> {
    const payload: IJwtPayload = {
      name: user.name,
      email: user.email,
      confirmed: user.confirmed,
      suspended: user.suspended,
    };
    return this._jwtService.sign(payload);
  }

  async resendPin(email: AuthResendCodeDto): Promise<boolean> {
    const user = await this.userModel.findOne({ email: email.email });
    if (user) {
      user.emailSent = false;
      // Generates a PIN to confirm the user later
      user.pin = generatePin()[0];
      await user.save();
      return true;
    }
    throw new InternalServerErrorException();
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async sendVerificationEmail() {
    sgMail.setApiKey(this._configService.get(ConfigEnum.SENDGRID_API_KEY));
    const unsentVerificationEmails = await this.userModel.find({
      emailSent: false,
    });
    const message = {
      to: '',
      from: 'me@axelespinosadev.com',
      subject: '',
      html: '',
    };

    for (const user of unsentVerificationEmails) {
      message.to = user.email;

      if (user.language === 'es') {
        message.html = generateVerificationCodeTemplate(user.name, user.pin);
        message.subject = 'Muvick Código de verificación';
      } else if (user.language === 'en') {
        message.html = generateVerificationCodeTemplateEnglish(
          user.name,
          user.pin,
        );
        message.subject = 'Muvick Verification Code';
      }

      try {
        const messageSent = await sgMail.send(message);
        if (messageSent[0].statusCode === 202) {
          user.emailSent = true;
          user.expirationDate = moment()
            .add(3, 'days')
            .format();
          user.save();
        }
      } catch (err) {
        console.error(`[Error Sending Verification Code] ${err.mediaDevices}`);
        console.error(err.stack);
      }
    }
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async suspendService() {
    const users = await this.userModel.find({
      confirmed: false,
      emailSent: true,
    });
    for (const user of users) {
      const expired = moment(user.expirationDate).isBefore(moment().format());
      if (expired) {
        user.suspended = true;
        await user.save();
      }
    }
  }
}
