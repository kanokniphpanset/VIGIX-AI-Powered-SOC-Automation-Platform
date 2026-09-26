import { PolicyPriority, ResponsibleRole } from "../../domain/entities/PolicyEvaluationTypes";

/**
 * PolicyEvaluationResultDto — the single, fully-merged answer returned by
 * PolicyEvaluator.evaluate(). Unlike PolicyResultFragment (one matched
 * rule's partial opinion), every field here is settled: booleans default
 * to false, arrays are deduped, and priority/roles are null rather than
 * undefined when nothing matched. See PolicyPrecedence.ts for the exact
 * merge algorithm and the reasoning behind each field's merge strategy.
 */
export interface PolicyEvaluationResultDto {
  priority: PolicyPriority | null;

  responsibleRole: ResponsibleRole | null;

  reviewRequired: boolean;
  reviewRole: ResponsibleRole | null;

  approvalRequired: boolean;
  approvalRole: ResponsibleRole | null;
  approvalReason: string[];

  highRiskReview: boolean;
  responseRequired: boolean;

  investigationRequired: boolean;
  additionalInvestigation: boolean;
  standardInvestigation: boolean;

  incidentStatus: string | null;
  requireNewInvestigation: boolean;
  requireNewRecommendation: boolean;
  requireEscalation: boolean;
  requireAdditionalEvidence: boolean;

  firstResponseSlaMinutes: number | null;
  resolutionSlaMinutes: number | null;

  /** Explainability: which rules/policies actually fired, for the UI's
   * "why is this ticket sensitive?" affordance. */
  matchedRuleIds: string[];
  matchedPolicyIds: string[];
}

export function emptyPolicyEvaluationResult(): PolicyEvaluationResultDto {
  return {
    priority: null,
    responsibleRole: null,
    reviewRequired: false,
    reviewRole: null,
    approvalRequired: false,
    approvalRole: null,
    approvalReason: [],
    highRiskReview: false,
    responseRequired: false,
    investigationRequired: false,
    additionalInvestigation: false,
    standardInvestigation: false,
    incidentStatus: null,
    requireNewInvestigation: false,
    requireNewRecommendation: false,
    requireEscalation: false,
    requireAdditionalEvidence: false,
    firstResponseSlaMinutes: null,
    resolutionSlaMinutes: null,
    matchedRuleIds: [],
    matchedPolicyIds: [],
  };
}
