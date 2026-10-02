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


