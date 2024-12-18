import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../../prisma';
import { authenticator } from 'otplib';

@Injectable()
export class OtpAuthenticationService {
  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async generateSecret(email: string) {
    const secret = authenticator.generateSecret();
    const appName = this.configService.getOrThrow('TFA_APP_NAME');
    const uri = authenticator.keyuri(email, appName, secret);
    return {
      uri,
      secret,
    };
  }

  verifyCode(code: string, secret: string) {
    return authenticator.verify({
      token: code,
      secret,
    });
  }

  async enableTwoFactorForUser(email: string, secret: string) {
    const { id } = await this.prisma.user.findFirst({
      where: { email },
      select: { id: true },
    });
    console.log(id);
    await this.prisma.user.update({
      where: { id },
      data: {
        twoFactorSecret: secret,
        isTwoFactorEnabled: true,
      },
    });
  }
}
