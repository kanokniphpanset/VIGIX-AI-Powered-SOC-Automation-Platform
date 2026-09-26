import { PolicyCondition } from "../../domain/entities/PolicyCondition";
import { PolicyResultFragment } from "../../domain/entities/PolicyEvaluationTypes";
import { UpdatePolicyInput } from "../../domain/repositories/IPolicyRepository";

export interface UpdatePolicyRuleDto {
  condition: PolicyCondition;
  result: PolicyResultFragment;
}

export interface UpdatePolicyDto {
  name?: string;
  description?: string | null;
  precedence?: number;
  rules?: UpdatePolicyRuleDto[];
}

/** Note: type/code/tenantId are deliberately not editable here — matches
 * IPolicyRepository.update()'s signature, which never accepts them.
 * Changing a policy's type or tenant is a delete+recreate, not an update. */
export function toUpdatePolicyInput(dto: UpdatePolicyDto): UpdatePolicyInput {
  if (dto.precedence !== undefined && !Number.isFinite(dto.precedence)) {
    throw new Error("precedence must be a number");
  }
  if (dto.rules !== undefined) {
    if (dto.rules.length === 0) throw new Error("rules, if provided, cannot be empty");
    for (const rule of dto.rules) {
      if (!rule.condition) throw new Error("every rule must have a condition");
      if (!rule.result || typeof rule.result !== "object") throw new Error("every rule must have a result");
    }
  }
  return {
    name: dto.name,
    description: dto.description,
    precedence: dto.precedence,
    rules: dto.rules?.map((r) => ({ condition: r.condition, result: r.result })),
  };
}
