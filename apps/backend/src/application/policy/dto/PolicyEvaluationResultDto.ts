import { PolicyPriority, ResponsibleRole, Severity } from "../../../domain/policy/entities/PolicyEvaluationTypes";

/**
 * PolicyEvaluationResultDto — the API/use-case response shape for
 * POST /api/policies/evaluate. `null` (not omission) marks "no matched rule
 * set this field" so API consumers never have to distinguish "false" from
 * "absent" for the non-boolean fields.
 */
export interface PolicyEvaluationResultDto {
  matchedPolicies: string[];
  /** Same values as matchedPolicies — every seeded policy today maps 1:1 to
   * exactly one rule, so "matched policy code" and "matched rule id" are the
   * same string (e.g. "RULE-A03"). Kept as a separate field per the
   * explainability requirement, additive alongside matchedPolicies rather
   * than replacing it (existing callers read matchedPolicies). */
  matchedRules: string[];

  priority: PolicyPriority | null;
  severity: Severity | null;

  responsibleRole: ResponsibleRole | null;

  reviewRequired: boolean;
  reviewRole: ResponsibleRole | null;

  approvalRequired: boolean;
  approvalRole: ResponsibleRole | null;
  /** Explainability: which condition(s) drove approvalRequired, e.g.
   * ["CRITICAL_ASSET", "HIGH_IMPACT_ACTION"]. Empty when approval isn't required. */
  approvalReason: string[];
  /** Approvers — always ["IR_TEAM"] in the two-role workflow. */
  approvalChain: ResponsibleRole[];
  /** Who executes the response (Human executes). Default IR_TEAM; independent of responsibleRole. */
  executorRole: ResponsibleRole;
  /** INTAKE: false = the alert waits for SOC triage instead of opening an Incident automatically. */
  autoCreateIncident: boolean;

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

  sla: { firstResponseMinutes: number; resolutionMinutes: number } | null;

  /** Convenience grouping of the VERIFICATION/ESCALATION-group flat fields
   * above (kept flat too, additive — CreateVerification.usecase.ts reads
   * the flat fields directly). */
  verificationOverrides: {
    incidentStatus: string | null;
    requireNewInvestigation: boolean;
    requireNewRecommendation: boolean;
    requireEscalation: boolean;
    requireAdditionalEvidence: boolean;
  };
}
