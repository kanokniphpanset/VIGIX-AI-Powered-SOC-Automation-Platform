import { Policy } from "../../domain/policy/entities/Policy.entity";
import { PolicyEvaluationInput, PolicyResultFragment } from "../../domain/policy/entities/PolicyEvaluationTypes";
import { matchesCondition } from "./PolicyMatcher";
import { EvaluatorOutcome } from "./AssignmentEvaluator";

/**
 * ApprovalEvaluator — answers ONLY "does this need review/approval, and by
 * whom?" (RULE-P01..P06). Approval is multi-factor (severity,
 * assetCriticality, actionImpactLevel) and deliberately NEVER keyed on
 * severity alone — see RULE-P01..P06 in policy.seed.ts and TEST 5/6/7 in
 * the Policy Engine test suite for the exact boundary this enforces
 * (the reason tags IR sees on a Response Ticket).
 */
export class ApprovalEvaluator {
  evaluate(policies: Policy[], input: PolicyEvaluationInput): EvaluatorOutcome {
    const fragments: PolicyResultFragment[] = [];
    const matchedCodes: string[] = [];

    for (const policy of policies.filter((p) => p.type === "APPROVAL")) {
      for (const rule of policy.activeRules()) {
        if (matchesCondition(rule.condition, input)) {
          fragments.push(rule.result);
          matchedCodes.push(policy.code);
        }
      }
    }

    return { fragments, matchedCodes };
  }
}
