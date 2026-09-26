import { Policy } from "../../domain/entities/Policy.entity";
import { PolicyRule } from "../../domain/entities/PolicyRule.entity";
import { PolicyCondition } from "../../domain/entities/PolicyCondition";
import { PolicyResultFragment } from "../../domain/entities/PolicyEvaluationTypes";
import { IPolicyRepository, NewPolicyInput, UpdatePolicyInput } from "../../domain/repositories/IPolicyRepository";

/**
 * ASSUMPTION — this file could not be verified against your actual
 * schema.prisma, which wasn't part of what was shared. It assumes:
 *   - a PrismaClient instance injected in the constructor (this repo's own
 *     convention elsewhere, matching PrismaPolicyRepository / Prisma*Repository
 *     naming used by the sibling repositories referenced in Policy.entity.ts).
 *   - two models, `policy` and `policyRule`, with `policyRule.policyId`
 *     as the foreign key and `condition`/`result` stored as Json columns.
 *   - `policy.type` stored as a String/enum matching PolicyType.
 * If your schema differs, only the four mapping helpers at the bottom
 * (toDomainPolicy / toDomainRule / prisma select shapes) need to change —
 * every method above them just calls this.prisma.policy.* and maps the
 * result, so the public IPolicyRepository contract is unaffected.
 */

interface PrismaClientLike {
  policy: {
    findFirst(args: any): Promise<any>;
    findMany(args: any): Promise<any[]>;
    create(args: any): Promise<any>;
    update(args: any): Promise<any>;
  };
  $transaction<T>(fn: (tx: any) => Promise<T>): Promise<T>;
}

export class PrismaPolicyRepository implements IPolicyRepository {
  constructor(private readonly prisma: PrismaClientLike) {}

  async findById(id: string, tenantId: string): Promise<Policy | null> {
    const row = await this.prisma.policy.findFirst({
      where: { id, tenantId },
      include: { rules: true },
    });
    return row ? PrismaPolicyRepository.toDomainPolicy(row) : null;
  }

  async findByCode(code: string, tenantId: string): Promise<Policy | null> {
    const row = await this.prisma.policy.findFirst({
      where: { code, tenantId },
      include: { rules: true },
    });
    return row ? PrismaPolicyRepository.toDomainPolicy(row) : null;
  }

  async findAll(tenantId: string): Promise<Policy[]> {
    const rows = await this.prisma.policy.findMany({
      where: { tenantId },
      include: { rules: true },
      orderBy: { precedence: "asc" },
    });
    return rows.map(PrismaPolicyRepository.toDomainPolicy);
  }

  async findAllEnabled(tenantId: string): Promise<Policy[]> {
    const rows = await this.prisma.policy.findMany({
      where: { tenantId, enabled: true },
      // Only enabled rules — evaluate() must never see a disabled rule.
      include: { rules: { where: { enabled: true } } },
      orderBy: { precedence: "asc" },
    });
    return rows.map(PrismaPolicyRepository.toDomainPolicy);
  }

  async create(input: NewPolicyInput): Promise<Policy> {
    const row = await this.prisma.policy.create({
      data: {
        tenantId: input.tenantId,
        code: input.code,
        name: input.name,
        description: input.description,
        type: input.type,
        precedence: input.precedence,
        enabled: true,
        version: 1,
        rules: {
          create: input.rules.map((r) => ({
            condition: r.condition as any,
            result: r.result as any,
            enabled: true,
          })),
        },
      },
      include: { rules: true },
    });
    return PrismaPolicyRepository.toDomainPolicy(row);
  }

  async update(id: string, tenantId: string, input: UpdatePolicyInput): Promise<Policy> {
    return this.prisma.$transaction(async (tx: any) => {
      if (input.rules) {
        // Replace-all semantics: simplest to reason about given rules have
        // no independent identity the API exposes for partial patching.
        await tx.policyRule.deleteMany({ where: { policyId: id } });
      }
      const row = await tx.policy.update({
        where: { id, tenantId },
        data: {
          name: input.name,
          description: input.description,
          precedence: input.precedence,
          version: { increment: 1 },
          ...(input.rules
            ? {
                rules: {
                  create: input.rules.map((r) => ({
                    condition: r.condition as any,
                    result: r.result as any,
                    enabled: true,
                  })),
                },
              }
            : {}),
        },
        include: { rules: true },
      });
      return PrismaPolicyRepository.toDomainPolicy(row);
    });
  }

  async setEnabled(id: string, tenantId: string, enabled: boolean): Promise<Policy> {
    const row = await this.prisma.policy.update({
      where: { id, tenantId },
      data: { enabled },
      include: { rules: true },
    });
    return PrismaPolicyRepository.toDomainPolicy(row);
  }

  private static toDomainPolicy(row: any): Policy {
    return Policy.create({
      id: row.id,
      tenantId: row.tenantId,
      code: row.code,
      name: row.name,
      description: row.description ?? null,
      type: row.type,
      enabled: row.enabled,
      version: row.version,
      precedence: row.precedence,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      rules: (row.rules ?? []).map(PrismaPolicyRepository.toDomainRule),
    });
  }

  private static toDomainRule(row: any): PolicyRule {
    return PolicyRule.create({
      id: row.id,
      policyId: row.policyId,
      condition: row.condition as PolicyCondition,
      result: row.result as PolicyResultFragment,
      enabled: row.enabled,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
}
