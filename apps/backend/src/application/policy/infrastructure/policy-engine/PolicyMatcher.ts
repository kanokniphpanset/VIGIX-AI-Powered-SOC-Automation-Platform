import {
  PolicyCondition,
  ConditionOperator,
  PolicyConditionLeaf,
  isConditionAll,
  isConditionAny,
  isConditionLeaf,
} from "../../domain/entities/PolicyCondition";
import { PolicyEvaluationInput } from "../../domain/entities/PolicyEvaluationTypes";

/**
 * PolicyMatcher — pure, side-effect-free evaluation of a PolicyCondition
 * tree against a PolicyEvaluationInput. This is the ONLY place condition
 * JSON is interpreted; it is a plain switch over `operator`, so a
 * PolicyCondition can never execute arbitrary code (see PolicyCondition.ts
 * docstring).
 *
 * Design decision: a leaf whose `field` is missing/undefined on the input
 * never matches (rather than throwing), because most call sites only
 * supply the handful of fields relevant to that evaluation pass (e.g. a
 * VERIFICATION-only evaluation won't have `severity` set) — see
 * PolicyEvaluationTypes.ts's own note that every PolicyEvaluationInput
 * field is optional for exactly this reason.
 */
export class PolicyMatcher {
  static matches(condition: PolicyCondition, input: PolicyEvaluationInput): boolean {
    if (isConditionAll(condition)) {
      return condition.all.every((c) => PolicyMatcher.matches(c, input));
    }
    if (isConditionAny(condition)) {
      return condition.any.some((c) => PolicyMatcher.matches(c, input));
    }
    if (isConditionLeaf(condition)) {
      return PolicyMatcher.evaluateLeaf(condition, input);
    }
    // Exhaustiveness guard — PolicyCondition is a closed union of the three
    // shapes above, so this only fires if malformed JSON reaches here.
    throw new Error(`Unrecognized PolicyCondition shape: ${JSON.stringify(condition)}`);
  }

  private static evaluateLeaf(leaf: PolicyConditionLeaf, input: PolicyEvaluationInput): boolean {
    const actual = (input as Record<string, unknown>)[leaf.field];
    if (actual === undefined || actual === null) {
      return false;
    }
    return PolicyMatcher.compare(actual, leaf.operator, leaf.value);
  }

  private static compare(actual: unknown, operator: ConditionOperator, expected: string | number | boolean): boolean {
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
      default: {
        // Exhaustiveness guard for ConditionOperator.
        const _exhaustive: never = operator;
        throw new Error(`Unrecognized ConditionOperator: ${_exhaustive}`);
      }
    }
  }
}
