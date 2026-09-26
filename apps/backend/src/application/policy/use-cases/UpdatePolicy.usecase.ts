import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../../domain/policy/entities/Policy.entity";
import { Result } from "../../../shared/result/Result";
import { UpdatePolicyDto } from "../dto/UpdatePolicyDto";
import { PolicyAuditLogger } from "../../../infrastructure/database/postgres/repositories/PolicyAuditLogger";
import { PolicyCondition } from "../../../domain/policy/entities/PolicyCondition";

export interface UpdatePolicyInput extends UpdatePolicyDto {
  id: string;
  tenantId: string;
}

export class UpdatePolicyUseCase {
  constructor(
    private readonly policyRepository: IPolicyRepository,
    private readonly auditLogger: PolicyAuditLogger
  ) {}

  async execute(input: UpdatePolicyInput): Promise<Result<Policy, "NOT_FOUND">> {
    const existing = await this.policyRepository.findById(input.id, input.tenantId);
    if (!existing) {
      return Result.fail("NOT_FOUND");
    }

    const updated = await this.policyRepository.update(input.id, input.tenantId, {
      name: input.name,
      description: input.description,
      precedence: input.precedence,
      rules: input.rules?.map((r) => ({ condition: r.condition as PolicyCondition, result: r.result })),
    });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "policy.updated",
      policyId: updated.id,
      metadata: { code: updated.code, version: updated.version },
    });

    return Result.ok(updated);
  }
}
