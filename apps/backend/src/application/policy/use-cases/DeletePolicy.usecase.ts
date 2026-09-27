import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Result } from "../../../shared/result/Result";
import { PolicyAuditLogger } from "../../../infrastructure/database/postgres/repositories/PolicyAuditLogger";

export interface DeletePolicyInput {
  id: string;
  tenantId: string;
  actor: string;
  /** Why the policy is removed — optional, stored in the audit record when given. */
  reason?: string | null;
}

/**
 * Removes a Policy and its rules (Knowledge → Policies). Only FUTURE evaluations are affected: past incidents,
 * tickets and recommendations keep the policy codes / results they recorded. The full policy (rules included) is
 * copied into the audit record, so it can be recreated by hand if it was deleted by mistake.
 */
export class DeletePolicyUseCase {
  constructor(
    private readonly policyRepository: IPolicyRepository,
    private readonly auditLogger: PolicyAuditLogger
  ) {}

  async execute(input: DeletePolicyInput): Promise<Result<{ id: string; code: string }, "NOT_FOUND">> {
    const existing = await this.policyRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");

    await this.policyRepository.delete(input.id, input.tenantId);
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "DELETE_POLICY",
      policyId: input.id,
      metadata: { code: existing.code, name: existing.name, reason: input.reason ?? null, snapshot: existing.toJSON() },
    });
    return Result.ok({ id: input.id, code: existing.code });
  }
}
