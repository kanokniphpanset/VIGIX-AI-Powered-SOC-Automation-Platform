/**
 * PolicyEvaluationTypes — shared vocabulary for the Policy rule engine.
 *
 * Domain separation (see PolicyEvaluator's own docstring for the full
 * rationale): Severity is an input the engine reads but never writes.
 * Severity (LOW..CRITICAL) is the primary classification input. There is
 * no risk score: VIGIX decisions never read one (risk-score rules were retired).
 * Priority (P0-P3) is the engine's own output scale — it is NOT the same
 * concept as the existing Incident.priority column (low|medium|high|
 * critical, see domain/incident/entities/Incident.entity.ts). Nothing here
 * overwrites that field; a caller decides separately whether/how to apply
 * a Policy result to an Incident record.
 */

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const SEVERITIES: Severity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export type PolicyPriority = "P0" | "P1" | "P2" | "P3";

/** Team responsible for acting on/reviewing/approving an incident.
 * Deliberately distinct from User.role (admin | analyst | viewer), which is
 * an API access-control level, not a SOC team assignment — see the Policy
 * module's own README section in PolicyEvaluator.ts. VIGIX has exactly two operational roles:
 * SOC (investigates, sends to IR) and IR_TEAM (decides and executes). */
export type ResponsibleRole = "SOC" | "IR_TEAM";

/** How critical the affected asset is — independent of Incident/Alert severity.
 * No Asset model exists in this schema yet, so no real call site can supply this
 * today; the engine fully supports it so wiring a data source later is additive. */
export type AssetCriticality =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export const ASSET_CRITICALITIES: AssetCriticality[] = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

/** How impactful a specific Action is if executed — sourced from Action.impactLevel
 * (which only has LOW/MEDIUM/HIGH today) once a concrete action is chosen, e.g. in
 * CreateResponsePlan.usecase.ts. CRITICAL exists here for rules that may need it
 * even though no current catalog Action reaches that level. */
export type ActionImpactLevel =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export const ACTION_IMPACT_LEVELS: ActionImpactLevel[] = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

export type PolicyType =
  | "PRIORITY"
  | "ASSIGNMENT"
  | "APPROVAL"
  | "VERIFICATION"
  | "ESCALATION"
  | "INTAKE"
  /** Alert Inbox triage SLA targets per alert severity (triageSlaMinutes). Read on its own — never merged into the
   * response / approval / intake evaluation, so it cannot change any other Policy result. */
  | "TRIAGE_SLA";

export const POLICY_TYPES: PolicyType[] = [
  "PRIORITY",
  "ASSIGNMENT",
  "APPROVAL",
  "VERIFICATION",
  "ESCALATION",
  "INTAKE",
  "TRIAGE_SLA",
];

export type VerificationResult = "RESOLVED" | "NOT_RESOLVED";

export const VERIFICATION_RESULTS: VerificationResult[] = [
  "RESOLVED",
  "NOT_RESOLVED",
];

/**
 * PolicyEvaluationInput — the incident context handed to the engine.
 * Every field is optional because different policy groups key off different
 * fields (Priority/Assignment/Approval read severity, assetCriticality and
 * actionImpactLevel;
 * Verification/Escalation read verificationResult/spreadDetected/
 * threatContained). Validation (range/enum checks) happens in
 * PolicyEvaluationInput.dto.ts — this type is the already-validated shape.
 */
export interface PolicyEvaluationInput {
  severity?: Severity;
  assetCriticality?: AssetCriticality;
  actionImpactLevel?: ActionImpactLevel;
  verificationResult?: VerificationResult;
  spreadDetected?: boolean;
  threatContained?: boolean;
}

/**
 * PolicyResultFragment — what one matched PolicyRule contributes. The
 * engine collects one of these per matched rule, then merges all of them
 * per PolicyPrecedence.ts into a single PolicyEvaluationResultDto. Every
 * field is optional: a given rule only sets the fields its own group cares
 * about (e.g. an ASSIGNMENT rule only ever sets responsibleRole).
 */
export interface PolicyResultFragment {
  priority?: PolicyPriority;
  responsibleRole?: ResponsibleRole;

  reviewRequired?: boolean;
  reviewRole?: ResponsibleRole;

  approvalRequired?: boolean;
  approvalRole?: ResponsibleRole;

  /** Approval chain. In the two-role workflow it is always ["IR_TEAM"] (the only approver). */
  approvalChain?: ResponsibleRole[];

  /** Who EXECUTES the response (Human executes) — distinct from responsibleRole (who owns the case). */
  executorRole?: ResponsibleRole;

  /** INTAKE: whether an ingested alert opens an Incident automatically. `false` wins when merged —
   * the alert then waits in the Alert Inbox for SOC triage. */
  autoCreateIncident?: boolean;

  /** Explainability tags for the UI ("why is this ticket sensitive?").
   * Merged as a deduped union across all matched fragments — see PolicyPrecedence.ts. */
  approvalReason?: string[];

  highRiskReview?: boolean;
  responseRequired?: boolean;

  investigationRequired?: boolean;
  additionalInvestigation?: boolean;
  standardInvestigation?: boolean;

  incidentStatus?: string;

  requireNewInvestigation?: boolean;
  requireNewRecommendation?: boolean;
  requireEscalation?: boolean;
  requireAdditionalEvidence?: boolean;

  /** Minutes. The engine takes the MINIMUM across matched rules
   * (the stricter/shorter deadline wins) — see PolicyPrecedence.ts. */
  firstResponseSlaMinutes?: number;
  /** TRIAGE_SLA policies: minutes the SOC has to triage an alert of the matching severity. */
  triageSlaMinutes?: number;

  /** Minutes. The engine takes the MINIMUM across matched rules
   * (the stricter/shorter deadline wins) — see PolicyPrecedence.ts. */
  resolutionSlaMinutes?: number;
}