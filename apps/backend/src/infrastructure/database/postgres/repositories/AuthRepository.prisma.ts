import { PrismaClient } from "@prisma/client";

export interface AuthUserRecord {
  id: string;
  tenantId: string;
  role: string;
  passwordHash: string;
}

export class PrismaAuthRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findByEmail(email: string): Promise<AuthUserRecord | null> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) return null;
    return { id: user.id, tenantId: user.tenantId, role: user.role, passwordHash: user.passwordHash };
  }
}
