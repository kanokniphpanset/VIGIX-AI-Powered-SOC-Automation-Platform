import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../../domain/policy/entities/Policy.entity";
import { Result } from "../../../shared/result/Result";
import { CreatePolicyDto } from "../dto/CreatePolicyDto";
import { PolicyAuditLogger } from "../../../infrastructure/database/postgres/repositories/PolicyAuditLogger";
import { PolicyCondition } from "../../../domain/policy/entities/PolicyCondition";

export interface CreatePolicyInput extends CreatePolicyDto {
  tenantId: string;
}

export class CreatePolicyUseCase {
  constructor(
    private readonly policyRepository: IPolicyRepository,
    private readonly auditLogger: PolicyAuditLogger
  ) {}

  async execute(input: CreatePolicyInput): Promise<Result<Policy, "DUPLICATE_CODE">> {
    const existing = await this.policyRepository.findByCode(input.code, input.tenantId);
    if (existing) {
      return Result.fail("DUPLICATE_CODE");
    }

    const policy = await this.policyRepository.create({
      tenantId: input.tenantId,
      code: input.code,
      name: input.name,
      description: input.description ?? null,
      type: input.type as Policy["type"],
      precedence: input.precedence,
      rules: input.rules.map((r) => ({ condition: r.condition as PolicyCondition, result: r.result })),
    });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "policy.created",
      policyId: policy.id,
      metadata: { code: policy.code },
    });

    return Result.ok(policy);
  }
}
