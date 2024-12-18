import { Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../../prisma';
import { authenticator } from 'otplib';

@Injectable()
export class OtpAuthenticationService {
  private readonly logger = new Logger(OtpAuthenticationService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async generateSecret(email: string) {
    if (!email) {
      throw new UnauthorizedException('User email required');
    }
    const user = await this.prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
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
    const user = await this.prisma.user.findFirst({
      where: { email },
    });
    this.logger.log(`Enabling 2FA for user ${email}`);
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        twoFactorSecret: secret,
        isTwoFactorEnabled: true,
      },
    });
  }
}
