import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../../domain/policy/entities/Policy.entity";
import { Result } from "../../../shared/result/Result";
import { PolicyAuditLogger } from "../../../infrastructure/database/postgres/repositories/PolicyAuditLogger";

export interface DisablePolicyInput {
  id: string;
  tenantId: string;
  actor: string;
}

export class DisablePolicyUseCase {
  constructor(
    private readonly policyRepository: IPolicyRepository,
    private readonly auditLogger: PolicyAuditLogger
  ) {}

  async execute(input: DisablePolicyInput): Promise<Result<Policy, "NOT_FOUND">> {
    const existing = await this.policyRepository.findById(input.id, input.tenantId);
    if (!existing) {
      return Result.fail("NOT_FOUND");
    }

    const updated = await this.policyRepository.setEnabled(input.id, input.tenantId, false);

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "policy.disabled",
      policyId: updated.id,
      metadata: { code: updated.code },
    });

    return Result.ok(updated);
  }
}
