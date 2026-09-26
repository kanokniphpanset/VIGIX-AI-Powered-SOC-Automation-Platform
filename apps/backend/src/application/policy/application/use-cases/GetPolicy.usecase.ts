import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { Policy } from "../../domain/entities/Policy.entity";

export class GetPolicyUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  async execute(id: string, tenantId: string): Promise<Policy> {
    const policy = await this.policyRepository.findById(id, tenantId);
    if (!policy) {
      throw new Error(`Policy ${id} not found`);
    }
    return policy;
  }
}
