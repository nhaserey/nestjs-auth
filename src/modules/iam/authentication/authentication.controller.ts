import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { Public } from '../authorization/decorators/public.decorator';
import { AuthType } from '../enums/auth-type.enum';
import { Auth } from '../decorators/auth.decorator';
import { ActiveUser } from '../decorators/active-user.decorator';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { Response } from 'express';
import { OtpAuthenticationService } from './otp-authentication.service';
import { toFileStream } from 'qrcode';

@Controller('authentication')
export class AuthenticationController {
  constructor(
    private readonly authenticationService: AuthenticationService,
    private readonly otpAuthService: OtpAuthenticationService,
  ) {}

  @Public()
  @Post('sign-up')
  async signUp(@Body() signUpDto: SignUpDto) {
    return this.authenticationService.signUp(signUpDto);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(@Body() signInDto: SignInDto) {
    return this.authenticationService.signIn(signInDto);
  }

  @Public()
  @Post('refresh-tokens')
  async refreshToken(@Body() refreshToken: RefreshTokenDto) {
    return this.authenticationService.refreshTokens(refreshToken);
  }

  @Auth(AuthType.Bearer)
  @HttpCode(HttpStatus.OK)
  @Post('2fa/generate')
  async generate2FAQrCode(
    @ActiveUser() user: ActiveUserData,
    @Res() response: Response,
  ) {
    console.log('generate2FAQrCode', user);
    const { secret, uri } = await this.otpAuthService.generateSecret(
      user.email,
    );
    await this.otpAuthService.enableTwoFactorForUser(user.email, secret);
    response.type('png');
    return toFileStream(response, uri);
  }
}
