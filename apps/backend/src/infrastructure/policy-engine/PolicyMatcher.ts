import { PolicyCondition, isConditionAll, isConditionAny, isConditionLeaf } from "../../domain/policy/entities/PolicyCondition";
import { PolicyEvaluationInput } from "../../domain/policy/entities/PolicyEvaluationTypes";

/**
 * PolicyMatcher — pure, side-effect-free evaluation of a PolicyCondition
 * tree against an incident context. No eval()/Function() anywhere: this is
 * a plain switch over a closed set of operators, so a condition read out of
 * the database can never execute arbitrary code (see PolicyCondition.ts's
 * own docstring).
 *
 * A field absent from the context never matches (missing data is not an
 * implicit wildcard).
 *
 * Retired fields (RETIRED_CONDITION_FIELDS, e.g. the legacy `riskScore`) never match, even if an old rule row
 * still references them and even if a caller smuggles the value into the context: Risk Score is not a decision
 * input in VIGIX — Severity is.
 */
export const RETIRED_CONDITION_FIELDS: readonly string[] = ["riskScore"];

export function matchesCondition(condition: PolicyCondition, context: PolicyEvaluationInput): boolean {
  if (isConditionAll(condition)) {
    return condition.all.every((c) => matchesCondition(c, context));
  }
  if (isConditionAny(condition)) {
    return condition.any.some((c) => matchesCondition(c, context));
  }
  if (isConditionLeaf(condition)) {
    if (RETIRED_CONDITION_FIELDS.includes(condition.field)) return false;
    const actual = (context as Record<string, unknown>)[condition.field];
    if (actual === undefined || actual === null) {
      return false;
    }
    return compare(actual, condition.operator, condition.value);
  }
  return false;
}

function compare(actual: unknown, operator: string, expected: unknown): boolean {
  switch (operator) {
    case "eq":
      return actual === expected;
    case "neq":
      return actual !== expected;
    case "gte":
      return typeof actual === "number" && typeof expected === "number" && actual >= expected;
    case "lte":
      return typeof actual === "number" && typeof expected === "number" && actual <= expected;
    case "gt":
      return typeof actual === "number" && typeof expected === "number" && actual > expected;
    case "lt":
      return typeof actual === "number" && typeof expected === "number" && actual < expected;
    default:
      return false;
  }
}
