import { Policy as PrismaPolicy, PolicyRule as PrismaPolicyRule } from "@prisma/client";
import { Policy } from "../../../../domain/policy/entities/Policy.entity";
import { PolicyRule } from "../../../../domain/policy/entities/PolicyRule.entity";
import { PolicyType } from "../../../../domain/policy/entities/PolicyEvaluationTypes";
import { PolicyCondition } from "../../../../domain/policy/entities/PolicyCondition";
import { PolicyResultFragment } from "../../../../domain/policy/entities/PolicyEvaluationTypes";

type PrismaPolicyWithRules = PrismaPolicy & { rules: PrismaPolicyRule[] };

export class PolicyMapper {
  static ruleToDomain(raw: PrismaPolicyRule): PolicyRule {
    return PolicyRule.create({
      id: raw.id,
      policyId: raw.policyId,
      condition: raw.condition as unknown as PolicyCondition,
      result: raw.result as unknown as PolicyResultFragment,
      enabled: raw.enabled,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
    });
  }

  static toDomain(raw: PrismaPolicyWithRules): Policy {
    return Policy.create({
      id: raw.id,
      tenantId: raw.tenantId,
      code: raw.code,
      name: raw.name,
      description: raw.description,
      type: raw.type as PolicyType,
      enabled: raw.enabled,
      version: raw.version,
      precedence: raw.precedence,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
      rules: raw.rules.map(PolicyMapper.ruleToDomain),
    });
  }
}
