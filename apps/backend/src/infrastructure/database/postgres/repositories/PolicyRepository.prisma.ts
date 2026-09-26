import { PrismaClient, Prisma } from "@prisma/client";
import { IPolicyRepository, NewPolicyInput, UpdatePolicyInput } from "../../../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../../../domain/policy/entities/Policy.entity";
import { PolicyMapper } from "../mappers/Policy.mapper";

const withRules = { rules: true } satisfies Prisma.PolicyInclude;

export class PrismaPolicyRepository implements IPolicyRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Policy | null> {
    const raw = await this.prisma.policy.findFirst({ where: { id, tenantId }, include: withRules });
    return raw ? PolicyMapper.toDomain(raw) : null;
  }

  async findByCode(code: string, tenantId: string): Promise<Policy | null> {
    const raw = await this.prisma.policy.findFirst({ where: { code, tenantId }, include: withRules });
    return raw ? PolicyMapper.toDomain(raw) : null;
  }

  async findAll(tenantId: string): Promise<Policy[]> {
    const rows = await this.prisma.policy.findMany({
      where: { tenantId },
      include: withRules,
      orderBy: [{ precedence: "asc" }, { code: "asc" }],
    });
    return rows.map(PolicyMapper.toDomain);
  }

  /** Enabled policies, with only their enabled rules — the evaluation
   * endpoint must never see a disabled policy or a disabled rule. */
  async findAllEnabled(tenantId: string): Promise<Policy[]> {
    const rows = await this.prisma.policy.findMany({
      where: { tenantId, enabled: true },
      include: { rules: { where: { enabled: true } } },
      orderBy: [{ precedence: "asc" }, { code: "asc" }],
    });
    return rows.map(PolicyMapper.toDomain);
  }

  async create(input: NewPolicyInput): Promise<Policy> {
    const raw = await this.prisma.policy.create({
      data: {
        tenantId: input.tenantId,
        code: input.code,
        name: input.name,
        description: input.description,
        type: input.type,
        precedence: input.precedence,
        rules: {
          create: input.rules.map((r) => ({
            condition: r.condition as unknown as Prisma.InputJsonValue,
            result: r.result as unknown as Prisma.InputJsonValue,
          })),
        },
      },
      include: withRules,
    });
    return PolicyMapper.toDomain(raw);
  }

  async update(id: string, tenantId: string, input: UpdatePolicyInput): Promise<Policy> {
    // Rules, when provided, are replaced wholesale — simpler and safer than
    // diffing individual rule rows, and matches how the seed re-declares a
    // policy's full rule set on every run (see prisma/seeds/policy.seed.ts).
    if (input.rules) {
      await this.prisma.policyRule.deleteMany({ where: { policyId: id } });
    }

    const raw = await this.prisma.policy.update({
      where: { id },
      data: {
        name: input.name,
        description: input.description,
        precedence: input.precedence,
        version: { increment: 1 },
        rules: input.rules
          ? {
              create: input.rules.map((r) => ({
                condition: r.condition as unknown as Prisma.InputJsonValue,
                result: r.result as unknown as Prisma.InputJsonValue,
              })),
            }
          : undefined,
      },
      include: withRules,
    });
    return PolicyMapper.toDomain(raw);
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.policy.findFirstOrThrow({ where: { id, tenantId }, select: { id: true } });
      await tx.policyRule.deleteMany({ where: { policyId: id } });
      await tx.policy.delete({ where: { id } });
    });
  }

  async setEnabled(id: string, tenantId: string, enabled: boolean): Promise<Policy> {
    const raw = await this.prisma.policy.update({
      where: { id },
      data: { enabled },
      include: withRules,
    });
    return PolicyMapper.toDomain(raw);
  }
}
