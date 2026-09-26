import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { Policy } from "../../domain/entities/Policy.entity";
import { CreatePolicyDto, toNewPolicyInput } from "../dto/CreatePolicy.dto";

export class CreatePolicyUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  async execute(dto: CreatePolicyDto): Promise<Policy> {
    const existing = await this.policyRepository.findByCode(dto.code, dto.tenantId);
    if (existing) {
      throw new Error(`Policy with code "${dto.code}" already exists for this tenant`);
    }
    return this.policyRepository.create(toNewPolicyInput(dto));
  }
}
