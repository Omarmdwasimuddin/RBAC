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
