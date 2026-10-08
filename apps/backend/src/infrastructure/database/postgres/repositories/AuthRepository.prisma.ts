import { Prisma, PrismaClient } from "@prisma/client";
import { AuditLogger } from "./AuditLogger";

export interface AuthUserRecord {
  id: string;
  tenantId: string;
  role: string;
  passwordHash: string;
}

export interface AuthCredentialRecord {
  id: string;
  tenantId: string;
  email: string;
  passwordHash: string;
}

export class PrismaAuthRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findByEmail(email: string): Promise<AuthUserRecord | null> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) return null;
    return { id: user.id, tenantId: user.tenantId, role: user.role, passwordHash: user.passwordHash };
  }

  /** The authenticated user's own credential, scoped to the tenant from the JWT. */
  async findCredentialById(id: string, tenantId: string): Promise<AuthCredentialRecord | null> {
    const user = await this.prisma.user.findFirst({ where: { id, tenantId }, select: { id: true, tenantId: true, email: true, passwordHash: true } });
    return user;
  }

  /** New hash + PASSWORD_CHANGED audit in one transaction (no password value is audited). */
  async updatePasswordHash(id: string, tenantId: string, passwordHash: string): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const { count } = await tx.user.updateMany({ where: { id, tenantId }, data: { passwordHash } });
      if (count !== 1) throw new Error("Password update did not match exactly one user");
      await new AuditLogger(tx).record({
        tenantId, actor: id, action: "PASSWORD_CHANGED", entity: "User", entityId: id, metadata: { selfService: true },
      });
    });
  }

  /** Whether another user already signs in with this email (case-insensitive; emails are unique across tenants). */
  async emailInUse(email: string, exceptUserId: string): Promise<boolean> {
    const other = await this.prisma.user.findFirst({ where: { email: { equals: email, mode: "insensitive" }, id: { not: exceptUserId } }, select: { id: true } });
    return !!other;
  }

  /** New email + EMAIL_CHANGED audit in one transaction; "EMAIL_TAKEN" when the unique index rejects it (race). */
  async updateEmail(id: string, tenantId: string, email: string, previousEmail: string): Promise<"OK" | "EMAIL_TAKEN"> {
    try {
      await this.prisma.$transaction(async (tx) => {
        const { count } = await tx.user.updateMany({ where: { id, tenantId }, data: { email } });
        if (count !== 1) throw new Error("Email update did not match exactly one user");
        await new AuditLogger(tx).record({
          tenantId, actor: id, action: "EMAIL_CHANGED", entity: "User", entityId: id, metadata: { selfService: true, previousEmail, email },
        });
      });
      return "OK";
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") return "EMAIL_TAKEN";
      throw e;
    }
  }
}
