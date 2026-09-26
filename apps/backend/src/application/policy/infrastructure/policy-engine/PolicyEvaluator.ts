import { Policy } from "../../domain/entities/Policy.entity";
import { PolicyEvaluationInput } from "../../domain/entities/PolicyEvaluationTypes";
import { PolicyEvaluationResultDto } from "../../application/dto/PolicyEvaluationResult.dto";
import { PolicyMatcher } from "./PolicyMatcher";
import { PolicyPrecedence, MatchedFragment } from "./PolicyPrecedence";

/**
 * PolicyEvaluator — the Policy Engine's single entry point.
 *
 *   PRIORITY RULES  → priority, responsibleRole, SLA minutes
 *   VERIFICATION RULES → incidentStatus, requireNewInvestigation /
 *     requireEscalation / requireAdditionalEvidence
 *   APPROVAL RULES  → approvalRequired/approvalRole, reviewRequired/reviewRole
 *
 * These groups are independent: this evaluator does not care which
 * PolicyType produced a match, it just runs every enabled Policy's enabled
 * PolicyRules against the input and merges whatever fires. Callers
 * (EvaluatePolicy.usecase.ts) are responsible for only passing the input
 * fields relevant to the moment being evaluated (e.g. don't pass
 * verificationResult until a Response has actually been verified), since a
 * field's mere presence is what lets its rules match.
 *
 * This engine deliberately does NOT know about Incident, Alert, Asset, or
 * any other entity — it only sees PolicyEvaluationInput. It also never
 * mutates anything: it returns a result, and it is entirely up to the
 * caller whether/how a matched result gets applied to an Incident record
 * (see PolicyEvaluationTypes.ts's own note on this, and Recommendation/
 * ResponsePlan's docstrings on why nothing here should ever trigger an
 * automated Response).
 */
export class PolicyEvaluator {
  static evaluate(policies: Policy[], input: PolicyEvaluationInput): PolicyEvaluationResultDto {
    const enabledPolicies = policies.filter((p) => p.enabled).sort((a, b) => a.precedence - b.precedence);

    const matched: MatchedFragment[] = [];
    for (const policy of enabledPolicies) {
      for (const rule of policy.activeRules()) {
        if (PolicyMatcher.matches(rule.condition, input)) {
          matched.push({ fragment: rule.result, ruleId: rule.id, policyId: policy.id });
        }
      }
    }

    return PolicyPrecedence.merge(matched);
  }
}
