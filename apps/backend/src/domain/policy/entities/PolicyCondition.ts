/**
 * PolicyCondition — declarative condition tree stored as PolicyRule.condition
 * (JSON column). This is data, never executable code: PolicyMatcher.ts
 * evaluates it with a plain switch over `operator`, so nothing here can ever
 * run arbitrary JavaScript against the database or the API.
 *
 * Examples (matching the seeded POL-001..017 rules):
 *   severity = CRITICAL
 *     { field: "severity", operator: "eq", value: "CRITICAL" }
 *
 *   severity = CRITICAL AND assetCriticality = CRITICAL
 *     { all: [
 *         { field: "severity", operator: "eq", value: "CRITICAL" },
 *         { field: "assetCriticality", operator: "eq", value: "CRITICAL" },
 *     ] }
 *
 *   severity = LOW OR severity = MEDIUM
 *     { any: [
 *         { field: "severity", operator: "eq", value: "LOW" },
 *         { field: "severity", operator: "eq", value: "MEDIUM" },
 *     ] }
 */

export type ConditionOperator = "eq" | "neq" | "gte" | "lte" | "gt" | "lt";

export type ConditionFieldName =
  | "severity"
  | "assetCriticality"
  | "actionImpactLevel"
  | "verificationResult"
  | "spreadDetected"
  | "threatContained";

export interface PolicyConditionLeaf {
  field: ConditionFieldName;
  operator: ConditionOperator;
  value: string | number | boolean;
}

export interface PolicyConditionAll {
  all: PolicyCondition[];
}

export interface PolicyConditionAny {
  any: PolicyCondition[];
}

export type PolicyCondition = PolicyConditionLeaf | PolicyConditionAll | PolicyConditionAny;

export function isConditionLeaf(condition: PolicyCondition): condition is PolicyConditionLeaf {
  return "field" in condition;
}
export function isConditionAll(condition: PolicyCondition): condition is PolicyConditionAll {
  return "all" in condition;
}
export function isConditionAny(condition: PolicyCondition): condition is PolicyConditionAny {
  return "any" in condition;
}
