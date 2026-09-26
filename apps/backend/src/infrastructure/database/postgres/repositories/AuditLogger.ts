import { PrismaClient, Prisma } from "@prisma/client";

/**
 * AuditLogger — generic writer for the existing AuditLog table, shared by
 * the Recommendation/Approval/Response/Verification modules (spec section
 * 34). PolicyAuditLogger stays as-is (Policy's own tested call sites are
 * untouched) — this is the "proper Audit module" its own docstring
 * anticipated, scoped to the newer modules to avoid touching already
 * verified Policy code.
 */
export class AuditLogger {
  constructor(private readonly prisma: PrismaClient | Prisma.TransactionClient) {}

  async record(input: {
    tenantId: string;
    actor: string;
    action: string;
    entity: string;
    entityId: string;
    metadata?: Record<string, unknown>;
  }): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        tenantId: input.tenantId,
        actor: input.actor,
        action: input.action,
        entity: input.entity,
        entityId: input.entityId,
        metadata: (input.metadata ?? {}) as Prisma.InputJsonValue,
      },
    });
  }
}
