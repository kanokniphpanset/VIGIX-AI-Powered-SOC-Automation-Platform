import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { Policy } from "../../domain/entities/Policy.entity";

export class DisablePolicyUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  async execute(id: string, tenantId: string): Promise<Policy> {
    return this.policyRepository.setEnabled(id, tenantId, false);
  }
}
