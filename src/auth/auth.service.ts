import { ConfigService } from '@nestjs/config';
import { PrismaService } from './../prisma/prisma.service';
import {
  ForbiddenException,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';

import { AuthDto } from './dto';
import { hash, verify } from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}
  async signup(auth: AuthDto) {
    // generate password
    const hashPassword = await hash(auth.password);
    // save user in the db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: auth.email,
          password: hashPassword
        }
      });
      delete user.password;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Email already exists in the database.');
        }
      }
    }
    // return created user
  }
  async signin(auth: AuthDto) {
    // find user by email
    const user = await this.prisma.user.findFirst({
      where: { email: auth.email }
    });

    // if email does not exist throw error
    if (!user) throw new UnauthorizedException('Credencials incorrect');
    // compare password
    const passwordMatches = await verify(user.password, auth.password);
    // if password are not equeal throw error
    if (!passwordMatches)
      throw new UnauthorizedException('Credencials incorrect');

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: string,
    email: string
  ): Promise<{ access_token: string }> {
    const payload = { sub: userId, email };
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET')
    });

    return { access_token: token };
  }
}
