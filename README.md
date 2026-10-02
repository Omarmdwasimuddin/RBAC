## NestJS Production-Level Roll-Base Authentication: Signup & Login
 
#### Prisma setup koro---> [Connect NestJ with Prisma and Supabase (Prisma v7.10.0)](https://github.com/Omarmdwasimuddin/Connect-NestJ-with-Prisma-and-Supabase-Prisma-v7.10.0-)
>#### Ekhane just schema.prisma hobe --->
```bash
generator client {
  provider = "prisma-client"
  output   = "../generated/prisma"
}

datasource db {
  provider = "postgresql"
}

enum Role {
  USER
  MODERATOR
  ADMIN
  SUPER_ADMIN
}

model User {
  id                String    @id @default(cuid())
  email             String    @unique
  password          String    // bcrypt hash, plain text kokhono na
  role Role @default(USER)

  refreshTokens     RefreshToken[]

  // Account lockout tracking
  failedLoginAttempts Int      @default(0)
  lockoutUntil        DateTime?

  // Timestamps
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt


  @@index([email])
  @@index([role])
  @@map("users")
}

model RefreshToken {
  id        String    @id // এটাই JWT-এর jti
  userId    String
  user      User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  expiresAt DateTime
  revokedAt DateTime?
  createdAt DateTime  @default(now())

  @@index([userId])
  @@map("refresh_tokens")
}
```
>#### er por migration korlei hobe.
---

#### [NestJS Production-Level Authentication: Signup & Login](https://github.com/Omarmdwasimuddin/NestJS-Production-Level-Signup-Login) ---> eta complete koro agee.


#### Create files
```bash
mkdir -p src/auth/types
```
```bash
mkdir -p src/common/decorators
```
```bash
mkdir -p src/admin/dto
```
```bash
New-Item -ItemType File -Path src/auth/types/auth-user.type.ts
```
```bash
New-Item -ItemType File -Path src/auth/guards/roles.guard.ts
```
```bash
New-Item -ItemType File -Path src/common/decorators/roles.decorator.ts
```
```bash
New-Item -ItemType File -Path src/common/decorators/auth.decorator.ts
```
```bash
New-Item -ItemType File -Path src/admin/dto/update-role.dto.ts
```
---

#### Generate Admin module, service, controller
```bash
nest g module admin
```
```bash
nest g service admin
```
```bash
nest g controller admin
```
---


#### `src/auth/types/auth-user.type.ts`
```bash
import { Role } from 'generated/prisma/client';

export interface AuthUser {
  sub: string;
  email: string;
  role: Role;
  iat?: number;
  exp?: number;
}
```
---


#### `src/common/decorators/roles.decorator.ts`
```bash
import { SetMetadata } from '@nestjs/common';
import { Role } from 'generated/prisma/client';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
```
---


#### `src/auth/guards/roles.guard.ts`
```bash
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { Role } from 'generated/prisma/client';
import { ROLES_KEY } from '../../common/decorators/roles.decorator';
import { AuthUser } from '../types/auth-user.type';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[] | undefined>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    // No @Roles() on the route -> only authentication is required
    if (!requiredRoles || requiredRoles.length === 0) return true;

    const request = context.switchToHttp().getRequest<Request>();
    const user = request['user'] as AuthUser | undefined;

    if (!user || !requiredRoles.includes(user.role)) {
      throw new ForbiddenException({
        message: 'You do not have permission to access this resource',
        errorType: 'AUTH_INSUFFICIENT_ROLE',
      });
    }

    return true;
  }
}
```
---


#### `src/common/decorators/auth.decorator.ts`
```bash
import { applyDecorators, UseGuards } from '@nestjs/common';
import { Role } from 'generated/prisma/client';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from './roles.decorator';

export function Auth(...roles: Role[]) {
  return applyDecorators(UseGuards(JwtAuthGuard, RolesGuard), Roles(...roles));
}
```
---


#### `auth.service.ts`
```bash
import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Prisma, Role } from 'generated/prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MS } from './auth.constants';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { PinoLogger, InjectPinoLogger } from 'nestjs-pino';

const BCRYPT_ROUNDS = 12;

@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS = BCRYPT_ROUNDS;
  private readonly dummyHash = bcrypt.hashSync('dummy-password-for-timing', BCRYPT_ROUNDS);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @InjectPinoLogger(AuthService.name)
    private readonly logger: PinoLogger,
  ) {}

  async register(dto: RegisterDto) {
    const passwordHash = await bcrypt.hash(dto.password, this.SALT_ROUNDS);

    try {
      // role intentionally set kora hoy nai -> DB default USER
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: passwordHash,
        },
        select: {
          id: true,
          email: true,
          role: true,
          createdAt: true,
        },
      });

      return user;
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException({
          message: 'এই email দিয়ে already একটা account আছে',
          errorType: 'AUTH_EMAIL_EXISTS',
        });
      }

      throw error;
    }
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      await bcrypt.compare(dto.password, this.dummyHash);
      this.logger.warn({ email: dto.email }, 'Login attempt — user not found');
      throw new UnauthorizedException({
        message: 'Email অথবা password ভুল',
        errorType: 'AUTH_INVALID_CREDENTIALS',
      });
    }

    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
      const minutesLeft = Math.ceil(
        (user.lockoutUntil.getTime() - Date.now()) / 60000,
      );
      this.logger.warn({ userId: user.id }, 'Login attempt on locked account');
      throw new ForbiddenException({
        message: `অনেকবার ভুল চেষ্টার কারণে account সাময়িক লক আছে। ${minutesLeft} মিনিট পর আবার চেষ্টা করো`,
        errorType: 'AUTH_ACCOUNT_LOCKED',
      });
    }

    const passwordMatches = await bcrypt.compare(dto.password, user.password);

    if (!passwordMatches) {
      this.logger.warn({ userId: user.id }, 'Login failed — wrong password');
      await this.handleFailedLogin(user.id);

      throw new UnauthorizedException({
        message: 'Email অথবা password ভুল',
        errorType: 'AUTH_INVALID_CREDENTIALS',
      });
    }

    this.logger.info({ userId: user.id }, 'Login successful');

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockoutUntil: null,
      },
    });

    const tokens = await this.generateTokens(user.id, user.email, user.role);
    return {
      user: { id: user.id, email: user.email, role: user.role },
      ...tokens,
    };
  }

  private async generateTokens(userId: string, email: string, role: Role) {
    // Access token-e role thake, refresh token-e thake na
    const accessToken = this.jwtService.sign({ sub: userId, email, role });

    const jti = randomUUID();
    const refreshToken = this.jwtService.sign(
      { sub: userId, email },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<JwtSignOptions['expiresIn']>('JWT_REFRESH_EXPIRY'),
        jwtid: jti,
      },
    );

    const decoded = this.jwtService.decode<{ exp: number }>(refreshToken);
    await this.prisma.refreshToken.create({
      data: {
        id: jti,
        userId,
        expiresAt: new Date(decoded.exp * 1000),
      },
    });

    return { accessToken, refreshToken };
  }

  private async handleFailedLogin(userId: string) {
    const updated = await this.prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: { increment: 1 } },
      select: { failedLoginAttempts: true },
    });

    if (updated.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { lockoutUntil: new Date(Date.now() + LOCKOUT_DURATION_MS) },
      });
      this.logger.warn({ userId }, 'Account locked due to repeated failed logins');
    }
  }

  async refreshTokens(refreshToken: string) {
    let payload: { sub: string; email: string; jti?: string };

    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException({
        message: 'Refresh token invalid অথবা expired',
        errorType: 'AUTH_TOKEN_INVALID',
      });
    }

    if (!payload.jti) {
      throw new UnauthorizedException({
        message: 'Refresh token invalid অথবা expired',
        errorType: 'AUTH_TOKEN_INVALID',
      });
    }

    const revoked = await this.prisma.refreshToken.updateMany({
      where: { id: payload.jti, userId: payload.sub, revokedAt: null },
      data: { revokedAt: new Date() },
    });

    if (revoked.count === 0) {
      await this.prisma.refreshToken.updateMany({
        where: { userId: payload.sub, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      this.logger.warn(
        { userId: payload.sub },
        'Refresh token reuse detected — all sessions revoked',
      );
      throw new UnauthorizedException({
        message: 'Session invalid, আবার login করো',
        errorType: 'AUTH_TOKEN_REUSED',
      });
    }

    // role DB theke fresh ashe, tai role change hole next refresh-e update hoy
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      throw new UnauthorizedException({
        message: 'User খুঁজে পাওয়া যায়নি',
        errorType: 'AUTH_TOKEN_INVALID',
      });
    }

    const tokens = await this.generateTokens(user.id, user.email, user.role);
    return { user, ...tokens };
  }

  async logout(refreshToken?: string) {
    if (!refreshToken) return;

    try {
      const payload = await this.jwtService.verifyAsync<{ sub: string; jti?: string }>(
        refreshToken,
        { secret: this.configService.get<string>('JWT_REFRESH_SECRET') },
      );
      if (!payload.jti) return;

      await this.prisma.refreshToken.updateMany({
        where: { id: payload.jti, userId: payload.sub, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    } catch {
      // token invalid/expired হলে revoke করার কিছু নেই, logout তবু সফল ধরা হবে
    }
  }
}
```
---


#### ``
```bash

```
---



