import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { Policy } from "../../domain/entities/Policy.entity";

export class ListPoliciesUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  /** enabledOnly=true mirrors findAllEnabled — the same guarded read path
   * the evaluation endpoint uses; the admin UI's "manage policies" screen
   * should pass false to also see disabled/draft policies. */
  async execute(tenantId: string, enabledOnly = false): Promise<Policy[]> {
    return enabledOnly ? this.policyRepository.findAllEnabled(tenantId) : this.policyRepository.findAll(tenantId);
  }
}
