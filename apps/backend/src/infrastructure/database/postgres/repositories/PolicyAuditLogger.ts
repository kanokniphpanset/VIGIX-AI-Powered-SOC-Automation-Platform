import { PrismaClient, Prisma } from "@prisma/client";

/**
 * PolicyAuditLogger — writes to the existing AuditLog table (see
 * schema.prisma's AuditLog model). No audit-writing code exists anywhere
 * else in this backend yet, so this is a new-but-minimal piece scoped
 * strictly to Policy mutations, not a generic cross-module Audit service —
 * satisfies "policy changes should be auditable if the existing backend
 * has AuditLog support" (the table already exists; nothing wrote to it).
 * If a proper Audit module is built later, this can be replaced with a call
 * into it without touching any Policy use-case's public contract.
 */
export class PolicyAuditLogger {
  constructor(private readonly prisma: PrismaClient) {}

  async record(input: { tenantId: string; actor: string; action: string; policyId: string; metadata?: Record<string, unknown> }): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        tenantId: input.tenantId,
        actor: input.actor,
        action: input.action,
        entity: "Policy",
        entityId: input.policyId,
        metadata: (input.metadata ?? {}) as Prisma.InputJsonValue,
      },
    });
  }
}
