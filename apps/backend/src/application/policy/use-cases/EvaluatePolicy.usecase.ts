import { PolicyEvaluator } from "../../../infrastructure/policy-engine/PolicyEvaluator";
import { PolicyEvaluationInput } from "../../../domain/policy/entities/PolicyEvaluationTypes";
import { PolicyEvaluationResultDto } from "../dto/PolicyEvaluationResultDto";

/**
 * EvaluatePolicyUseCase — the only entry point AI/LLM/RAG agents or any
 * other caller may use to get a Policy decision. It only reads enabled
 * policies (via PolicyEvaluator -> IPolicyRepository.findAllEnabled) and
 * runs the deterministic engine; it has no code path that can create,
 * modify, enable, or disable a policy. See PolicyEvaluator.ts for the full
 * "Policy is a rule engine, not AI" rationale.
 */
export class EvaluatePolicyUseCase {
  constructor(private readonly policyEvaluator: PolicyEvaluator) {}

  async execute(input: { tenantId: string; context: PolicyEvaluationInput }): Promise<PolicyEvaluationResultDto> {
    return this.policyEvaluator.evaluate(input.tenantId, input.context);
  }
}
