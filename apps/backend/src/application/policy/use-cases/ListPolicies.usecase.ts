import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../../domain/policy/entities/Policy.entity";

export class ListPoliciesUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  async execute(input: { tenantId: string }): Promise<Policy[]> {
    return this.policyRepository.findAll(input.tenantId);
  }
}
