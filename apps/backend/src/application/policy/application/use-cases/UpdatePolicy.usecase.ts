import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { Policy } from "../../domain/entities/Policy.entity";
import { UpdatePolicyDto, toUpdatePolicyInput } from "../dto/UpdatePolicy.dto";

export class UpdatePolicyUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  async execute(id: string, tenantId: string, dto: UpdatePolicyDto): Promise<Policy> {
    const existing = await this.policyRepository.findById(id, tenantId);
    if (!existing) {
      throw new Error(`Policy ${id} not found`);
    }
    return this.policyRepository.update(id, tenantId, toUpdatePolicyInput(dto));
  }
}
