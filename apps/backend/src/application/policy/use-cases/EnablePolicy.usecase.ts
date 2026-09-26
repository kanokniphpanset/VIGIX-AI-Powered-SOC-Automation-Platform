import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../../domain/policy/entities/Policy.entity";
import { Result } from "../../../shared/result/Result";
import { PolicyAuditLogger } from "../../../infrastructure/database/postgres/repositories/PolicyAuditLogger";

export interface EnablePolicyInput {
  id: string;
  tenantId: string;
  actor: string;
}

export class EnablePolicyUseCase {
  constructor(
    private readonly policyRepository: IPolicyRepository,
    private readonly auditLogger: PolicyAuditLogger
  ) {}

  async execute(input: EnablePolicyInput): Promise<Result<Policy, "NOT_FOUND">> {
    const existing = await this.policyRepository.findById(input.id, input.tenantId);
    if (!existing) {
      return Result.fail("NOT_FOUND");
    }

    const updated = await this.policyRepository.setEnabled(input.id, input.tenantId, true);

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "policy.enabled",
      policyId: updated.id,
      metadata: { code: updated.code },
    });

    return Result.ok(updated);
  }
}
