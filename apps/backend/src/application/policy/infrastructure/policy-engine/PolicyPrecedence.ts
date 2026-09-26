import { PolicyResultFragment, PolicyPriority, ResponsibleRole } from "../../domain/entities/PolicyEvaluationTypes";
import { PolicyEvaluationResultDto, emptyPolicyEvaluationResult } from "../../application/dto/PolicyEvaluationResult.dto";

export interface MatchedFragment {
  fragment: PolicyResultFragment;
  ruleId: string;
  policyId: string;
}

/** P0 is the worst/most urgent; used to pick the single "worst wins" priority
 * across every matched rule, regardless of which policy/precedence produced it. */
const PRIORITY_RANK: Record<PolicyPriority, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };

/** IR_TEAM outranks SOC when two fragments disagree on who owns a role field (two-role workflow). */
const ROLE_RANK: Record<ResponsibleRole, number> = { IR_TEAM: 1, SOC: 2 };

/**
 * PolicyPrecedence — merges every matched rule's PolicyResultFragment into
 * one PolicyEvaluationResultDto. This is the single place that decides
 * what happens when two rules disagree; every choice below is a documented
 * design decision, not an accident, and can be retuned per-field without
 * touching PolicyMatcher or PolicyEvaluator:
 *
 *   - priority / responsibleRole / reviewRole / approvalRole: "most severe
 *     wins" (lowest PolicyPriority / highest-authority Role).
 *   - every boolean flag (reviewRequired, approvalRequired, highRiskReview,
 *     responseRequired, investigationRequired, additionalInvestigation,
 *     standardInvestigation, requireNewInvestigation,
 *     requireNewRecommendation, requireEscalation,
 *     requireAdditionalEvidence): OR'd — true if ANY matched rule requires
 *     it, since these are all "at least one rule insists on this" gates,
 *     never something a laxer rule should be able to relax.
 *   - approvalReason: deduped union of every matched rule's reasons, so the
 *     UI can show "why" in full.
 *   - incidentStatus: last matched rule wins (in the order fragments are
 *     passed in, which PolicyEvaluator produces in ascending
 *     Policy.precedence order) — in practice only VERIFICATION rules ever
 *     set this, and they don't conflict with each other in the seed data.
 *   - firstResponseSlaMinutes / resolutionSlaMinutes: MINIMUM across
 *     matched rules (the stricter/shorter deadline wins) — see
 *     PolicyResultFragment's own docstring.
 */
export class PolicyPrecedence {
  static merge(matched: MatchedFragment[]): PolicyEvaluationResultDto {
    const result = emptyPolicyEvaluationResult();
    const approvalReasons = new Set<string>();

    for (const { fragment, ruleId, policyId } of matched) {
      result.matchedRuleIds.push(ruleId);
      if (!result.matchedPolicyIds.includes(policyId)) {
        result.matchedPolicyIds.push(policyId);
      }

      if (fragment.priority && PolicyPrecedence.isMoreSevere(fragment.priority, result.priority)) {
        result.priority = fragment.priority;
      }
      if (fragment.responsibleRole && PolicyPrecedence.outranks(fragment.responsibleRole, result.responsibleRole)) {
        result.responsibleRole = fragment.responsibleRole;
      }
      if (fragment.reviewRole && PolicyPrecedence.outranks(fragment.reviewRole, result.reviewRole)) {
        result.reviewRole = fragment.reviewRole;
      }
      if (fragment.approvalRole && PolicyPrecedence.outranks(fragment.approvalRole, result.approvalRole)) {
        result.approvalRole = fragment.approvalRole;
      }

      result.reviewRequired = result.reviewRequired || !!fragment.reviewRequired;
      result.approvalRequired = result.approvalRequired || !!fragment.approvalRequired;
      result.highRiskReview = result.highRiskReview || !!fragment.highRiskReview;
      result.responseRequired = result.responseRequired || !!fragment.responseRequired;
      result.investigationRequired = result.investigationRequired || !!fragment.investigationRequired;
      result.additionalInvestigation = result.additionalInvestigation || !!fragment.additionalInvestigation;
      result.standardInvestigation = result.standardInvestigation || !!fragment.standardInvestigation;
      result.requireNewInvestigation = result.requireNewInvestigation || !!fragment.requireNewInvestigation;
      result.requireNewRecommendation = result.requireNewRecommendation || !!fragment.requireNewRecommendation;
      result.requireEscalation = result.requireEscalation || !!fragment.requireEscalation;
      result.requireAdditionalEvidence = result.requireAdditionalEvidence || !!fragment.requireAdditionalEvidence;

      if (fragment.incidentStatus) {
        result.incidentStatus = fragment.incidentStatus;
      }

      for (const reason of fragment.approvalReason ?? []) {
        approvalReasons.add(reason);
      }

      if (fragment.firstResponseSlaMinutes !== undefined) {
        result.firstResponseSlaMinutes =
          result.firstResponseSlaMinutes === null
            ? fragment.firstResponseSlaMinutes
            : Math.min(result.firstResponseSlaMinutes, fragment.firstResponseSlaMinutes);
      }
      if (fragment.resolutionSlaMinutes !== undefined) {
        result.resolutionSlaMinutes =
          result.resolutionSlaMinutes === null
            ? fragment.resolutionSlaMinutes
            : Math.min(result.resolutionSlaMinutes, fragment.resolutionSlaMinutes);
      }
    }

    result.approvalReason = Array.from(approvalReasons);
    return result;
  }

  private static isMoreSevere(candidate: PolicyPriority, current: PolicyPriority | null): boolean {
    if (current === null) return true;
    return PRIORITY_RANK[candidate] < PRIORITY_RANK[current];
  }

  private static outranks(candidate: ResponsibleRole, current: ResponsibleRole | null): boolean {
    if (current === null) return true;
    return ROLE_RANK[candidate] < ROLE_RANK[current];
  }
}
