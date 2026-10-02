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


#### `src/admin/dto/update-role.dto.ts`
```bash
import { IsEnum } from 'class-validator';
import { Role } from 'generated/prisma/client';

export class UpdateRoleDto {
  @IsEnum(Role, { message: 'role must be a valid Role' })
  role!: Role;
}
```
---


#### `src/admin/admin.service.ts`
```bash
import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { Role } from 'generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { AuthUser } from '../auth/types/auth-user.type';

const USER_SELECT = {
  id: true,
  email: true,
  role: true,
  createdAt: true,
} as const;

@Injectable()
export class AdminService {
  constructor(
    private readonly prisma: PrismaService,
    @InjectPinoLogger(AdminService.name)
    private readonly logger: PinoLogger,
  ) {}

  async listUsers(page: number, limit: number) {
    const take = Math.min(Math.max(limit, 1), 100); // hard cap
    const skip = (Math.max(page, 1) - 1) * take;

    const [items, total] = await this.prisma.$transaction([
      this.prisma.user.findMany({
        skip,
        take,
        orderBy: { createdAt: 'desc' },
        select: USER_SELECT,
      }),
      this.prisma.user.count(),
    ]);

    return { items, total, page, limit: take };
  }

  async updateRole(actor: AuthUser, targetId: string, newRole: Role) {
    if (actor.sub === targetId) {
      throw new ForbiddenException({
        message: 'You cannot change your own role',
        errorType: 'ADMIN_SELF_ROLE_CHANGE',
      });
    }

    const target = await this.prisma.user.findUnique({
      where: { id: targetId },
      select: USER_SELECT,
    });

    if (!target) {
      throw new NotFoundException({
        message: 'User not found',
        errorType: 'USER_NOT_FOUND',
      });
    }

    if (target.role === newRole) return target;

    // Role update + revoke all sessions atomically,
    // so the old role cannot survive through an existing refresh token.
    const [updated] = await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: targetId },
        data: { role: newRole },
        select: USER_SELECT,
      }),
      this.prisma.refreshToken.updateMany({
        where: { userId: targetId, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);

    // Audit log
    this.logger.warn(
      { actorId: actor.sub, targetId, from: target.role, to: newRole },
      'User role changed',
    );

    return updated;
  }
}
```
---


#### `src/admin/admin.controller.ts`
```bash
import {
  Body,
  Controller,
  DefaultValuePipe,
  Get,
  Param,
  ParseIntPipe,
  Patch,
  Query,
  Req,
} from '@nestjs/common';
import type { Request } from 'express';
import { Role } from 'generated/prisma/client';
import { AdminService } from './admin.service';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Auth } from '../common/decorators/auth.decorator';
import { AuthUser } from '../auth/types/auth-user.type';

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Auth(Role.ADMIN, Role.SUPER_ADMIN)
  @Get('users')
  listUsers(
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
  ) {
    return this.adminService.listUsers(page, limit);
  }

  @Auth(Role.SUPER_ADMIN)
  @Patch('users/:id/role')
  updateRole(
    @Req() req: Request,
    @Param('id') id: string,
    @Body() dto: UpdateRoleDto,
  ) {
    return this.adminService.updateRole(req['user'] as AuthUser, id, dto.role);
  }
}
```
---


#### `src/admin/admin.module.ts`
```bash
import { Module } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule], // JwtService lagbe JwtAuthGuard-er jonno
  providers: [AdminService],
  controllers: [AdminController],
})
export class AdminModule {}
```
---


#### `auth.module.ts`
```bash
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import type { StringValue } from 'ms';

@Module({
  imports: [JwtModule.registerAsync({
    imports: [ConfigModule],
    inject: [ConfigService],
    useFactory: (config: ConfigService) => ({
      secret: config.getOrThrow<string>('JWT_ACCESS_SECRET'),
      signOptions: {
        expiresIn: config.get<StringValue>('JWT_ACCESS_EXPIRY'),
      },
    })
  }),],
  providers: [AuthService],
  controllers: [AuthController],
  exports: [JwtModule],
})
export class AuthModule {}
```
---


#### `auth.controller.ts`
```bash
import { Body, Controller, Post, HttpCode, HttpStatus, Res, Req, UnauthorizedException, Get } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto'
import type { Response, Request } from 'express';
import { UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Throttle } from '@nestjs/throttler';
import { generateCsrfToken } from '../common/csrf/csrf.config';
import { Auth } from '../common/decorators/auth.decorator';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 1 min-এ max 3 বার
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 1 min-এ max 5 বার
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, accessToken, refreshToken } = await this.authService.login(dto);

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // dev-এ HTTPS না থাকলে false লাগবে
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days, JWT_REFRESH_EXPIRY-র সাথে match রাখা
      path: '/auth', // শুধু auth routes-এ পাঠানো হবে
    });

    return { user, accessToken };
    // refreshToken response body-তে কখনো ফেরত যাবে না — শুধু cookie-তে
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(req.cookies?.['refresh_token']);

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/auth', // set করার সময়ের path-এর সাথে মিলতে হবে, নাহলে cookie মুছবে না
    });

    return { message: 'Logged out' };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const oldRefreshToken = (req as Request & { cookies?: Record<string, string> }).cookies?.['refresh_token'];

    if (!oldRefreshToken) {
      throw new UnauthorizedException('Refresh token পাওয়া যায়নি');
    }

    const { user, accessToken, refreshToken } =
      await this.authService.refreshTokens(oldRefreshToken);

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/auth',
    });

    return { user, accessToken };
  }

  @UseGuards(JwtAuthGuard)
  @Auth()
  @Get('me')
  getProfile(@Req() req: Request) {
    return req['user'];  // { sub, email, role, iat, exp }
  }

  @Get('csrf-token')
  getCsrfToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const token = generateCsrfToken(req, res);
    return { csrfToken: token };
  }

}
```
---


#### ``
```bash

```
---
