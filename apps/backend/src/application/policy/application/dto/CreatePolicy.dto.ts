import { PolicyType } from "../../domain/entities/PolicyEvaluationTypes";
import { PolicyCondition } from "../../domain/entities/PolicyCondition";
import { PolicyResultFragment } from "../../domain/entities/PolicyEvaluationTypes";
import { NewPolicyInput } from "../../domain/repositories/IPolicyRepository";

export interface CreatePolicyRuleDto {
  condition: PolicyCondition;
  result: PolicyResultFragment;
}

export interface CreatePolicyDto {
  tenantId: string;
  code: string;
  name: string;
  description?: string | null;
  type: PolicyType;
  precedence: number;
  rules: CreatePolicyRuleDto[];
}

/** Turns the wire-level DTO into the repository's NewPolicyInput,
 * throwing on anything the repository/entity would otherwise reject
 * later and less legibly. */
export function toNewPolicyInput(dto: CreatePolicyDto): NewPolicyInput {
  if (!dto.tenantId?.trim()) throw new Error("tenantId is required");
  if (!dto.code?.trim()) throw new Error("code is required");
  if (!dto.name?.trim()) throw new Error("name is required");
  if (!Number.isFinite(dto.precedence)) throw new Error("precedence must be a number");
  if (!Array.isArray(dto.rules) || dto.rules.length === 0) {
    throw new Error("policy must define at least one rule");
  }
  for (const rule of dto.rules) {
    if (!rule.condition) throw new Error("every rule must have a condition");
    if (!rule.result || typeof rule.result !== "object") throw new Error("every rule must have a result");
  }
  return {
    tenantId: dto.tenantId,
    code: dto.code,
    name: dto.name,
    description: dto.description ?? null,
    type: dto.type,
    precedence: dto.precedence,
    rules: dto.rules.map((r) => ({ condition: r.condition, result: r.result })),
  };
}
