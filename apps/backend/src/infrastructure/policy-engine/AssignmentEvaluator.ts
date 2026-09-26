import { Policy } from "../../domain/policy/entities/Policy.entity";
import { PolicyEvaluationInput, PolicyResultFragment } from "../../domain/policy/entities/PolicyEvaluationTypes";
import { matchesCondition } from "./PolicyMatcher";

export interface EvaluatorOutcome {
  fragments: PolicyResultFragment[];
  matchedCodes: string[];
}

/**
 * AssignmentEvaluator — answers ONLY "who is responsible for this
 * incident?" (RULE-A01..A04: severity -> responsibleRole, plus
 * reviewRequired/reviewRole for HIGH/CRITICAL). Deliberately does not
 * decide approval — see ApprovalEvaluator.ts. Reuses the same
 * matchesCondition PolicyMatcher every other evaluator uses; this class
 * only filters which policies it looks at (type === "ASSIGNMENT").
 */
export class AssignmentEvaluator {
  evaluate(policies: Policy[], input: PolicyEvaluationInput): EvaluatorOutcome {
    const fragments: PolicyResultFragment[] = [];
    const matchedCodes: string[] = [];

    for (const policy of policies.filter((p) => p.type === "ASSIGNMENT")) {
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
