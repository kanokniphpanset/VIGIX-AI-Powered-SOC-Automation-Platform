import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../../domain/policy/entities/Policy.entity";
import { Result } from "../../../shared/result/Result";

export class GetPolicyUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Policy, "NOT_FOUND">> {
    const policy = await this.policyRepository.findById(input.id, input.tenantId);
    if (!policy) {
      return Result.fail("NOT_FOUND");
    }
    return Result.ok(policy);
  }
}
