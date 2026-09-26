import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { PolicyEvaluationInputDto } from "../dto/PolicyEvaluationInput.dto";
import { PolicyEvaluationResultDto } from "../dto/PolicyEvaluationResult.dto";
import { PolicyEvaluator } from "../../infrastructure/policy-engine/PolicyEvaluator";

export class EvaluatePolicyUseCase {
  constructor(private readonly policyRepository: IPolicyRepository) {}

  async execute(tenantId: string, rawInput: Record<string, unknown>): Promise<PolicyEvaluationResultDto> {
    const input = PolicyEvaluationInputDto.validate(rawInput);
    // Only enabled policies (with only their enabled rules) may ever reach
    // the evaluator — see IPolicyRepository.findAllEnabled's own docstring.
    const policies = await this.policyRepository.findAllEnabled(tenantId);
    return PolicyEvaluator.evaluate(policies, input);
  }
}
