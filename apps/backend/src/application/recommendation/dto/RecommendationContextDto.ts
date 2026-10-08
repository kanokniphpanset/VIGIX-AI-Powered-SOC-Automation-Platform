/**
 * RecommendationContextDto — the ONLY input the AI (Fake or Llm
 * RecommendationAgent) ever sees. Built exclusively from facts already in
 * Postgres by RecommendationContextBuilder — never fabricated, never
 * re-derived via a second RAG/MITRE/threat-intel computation (see
 * infrastructure/ai/RecommendationAgent.ts's own module docstring for the
 * full boundary rationale). Fields with no real data available are left as
 * empty arrays / null, never invented.
 */
export interface RecommendationContextIoc {
  iocType: string;
  iocValue: string;
  source: string;
  reputationScore: number | null;
  /** Added by a human analyst to this investigation (Task 10.3: targetable like evidence-linked IOCs). */
  manual?: boolean;
  /** Stable citation id ("I1", "I2", ...) assigned by RecommendationContextBuilder; the AI cites this, not the value. */
  ref?: string;
  /** IP role in the triggering alert (source = data.srcip, destination = data.dstip); absent for non-IP / unknown. */
  networkRole?: "source" | "destination";
}

export interface RecommendationContextMitreMapping {
  techniqueId: string;
  tactic: string;
  confidence: number | null;
}

export interface RecommendationContextAction {
  code: string;
  name: string;
  category: string;
  impactLevel: string;
  defaultApprovalRequired: boolean;
}

export interface RecommendationContextRunbook {
  code: string;
  name: string;
  trigger: string | null;
  objective: string | null;
  procedure: string[];
  verificationCriteria: string[];
}

/** One Evidence row of the CURRENT investigation cycle (factual, SYSTEM or MANUAL origin). */
export interface RecommendationContextEvidence {
  type: string;
  source: string;
  origin: string;
  title: string;
  timestamp: string;
  host: string | null;
  ruleId: string | null;
  iocValues: string[];
  /** Stable citation id ("E1", "E2", ...) assigned by RecommendationContextBuilder; the AI cites this, not the title. */
  ref?: string;
}

/**
 * Resolves the evidence citations the AI may use (Task 10.3 stabilization): "E<n>" -> that cycle evidence row's
 * title, "I<n>" -> that IOC's value, and a recorded MITRE technique id -> itself. The AI never reproduces long
 * titles; it cites these short ids, and anything that does not resolve here is invented evidence.
 * Returns ref -> canonical recorded string (what gets persisted).
 */
export function citableEvidence(context: Pick<RecommendationContextDto, "evidence" | "iocs" | "mitreMappings">): Map<string, string> {
  const refs = new Map<string, string>();
  for (const e of context.evidence) if (e.ref) refs.set(e.ref, e.title);
  for (const i of context.iocs) if (i.ref) refs.set(i.ref, i.iocValue);
  for (const m of context.mitreMappings) refs.set(m.techniqueId, m.techniqueId);
  return refs;
}

/** The AI pipeline's own analysis of the alert (LlmAnalystAgent) — an interpretation, NOT evidence. */
export interface RecommendationContextAiAnalysis {
  summary: string;
  keyFindings: string[];
}

/** Policy Engine result for (this incident, one Action) — the ONLY source of role/approval (Task 10.3). */
export interface RecommendationContextPolicy {
  responsibleRole: string | null;
  reviewRequired: boolean;
  reviewRole: string | null;
  approvalRequired: boolean;
  approvalRole: string | null;
  matchedRules: string[];
}

/** The incident-level playbook selected deterministically by the backend (PlaybookSelector). */
export interface RecommendationContextPlaybook {
  code: string;
  name: string;
  version: string;
  incidentType: string;
  matchedTechniques: string[];
  allowedActions: string[];
  strategy: { stepOrder: number; title: string; description: string | null }[];
}

/** One Action the selected playbook allows, with its action-level Runbook and its Policy result. */
export interface RecommendationContextActionProcedure {
  actionCode: string;
  actionName: string;
  description: string | null;
  impactLevel: string;
  runbookCode: string | null;
  runbookObjective: string | null;
  procedure: string[];
  expectedResult: string | null;
  verificationCriteria: string[];
  policy: RecommendationContextPolicy;
  /** Knowledge: the Action applies to this incident's attack type (domain/knowledge). false -> never recommendable. */
  applicable?: boolean;
  /** Deterministic evidence check (ActionEvidence.ts): the Action's own + Policy-required evidence, and the recorded
   * targets that satisfy all of it. satisfied=false -> never recommendable in this cycle. */
  evidence?: { requirements: string[]; satisfied: boolean; missing: string[]; targets: string[]; analystConfirmed: string[] };
  /** ACTION_COMPLIANCE policies in force for this Action and what each requires. */
  compliance?: { policies: string[]; requiredEvidence: string[]; rules: { policy: string; requiredEvidence: string[] }[] };
}

/**
 * Attack-specific containment procedure (knowledge/playbooks/PB-STC-001/procedures/<ATTACK_TYPE>/*.yaml). A
 * Recommendation is built from it as ordered CHECK / ACTION / MANUAL steps:
 *   CHECK   investigation / decision step — never an executable Action;
 *   ACTION  a catalog Action (Policy, approval and evidence rules apply); `condition` must be confirmed before it runs;
 *   MANUAL  a containment control VIGIX cannot execute (e.g. a WAF rule) — done by people, never by the Action Executor.
 */
export type ProcedureItemType = "ACTION" | "CHECK" | "MANUAL";

export interface RecommendationContextProcedureItem {
  type: ProcedureItemType;
  text: string;
  /** ACTION only: the catalog Action code. */
  actionCode: string | null;
  /** ACTION: the containment.yaml condition of the Action. MANUAL / CHECK: null. */
  condition: string | null;
  /** MANUAL only: the item names an approver ("requires <who> approval"). */
  requiresApproval: boolean;
  approver: string | null;
}

export interface RecommendationContextProcedureStep {
  /** Evidence-gated knowledge items; empty/absent means applicable to the procedure generally. */
  appliesWhenTechniques?: string[];
  /** Offered only when at least one of these evidence signals (domain/knowledge/evidenceSignals.ts) is present. */
  appliesWhenSignals?: string[];
  /** The step starts the response of another attack type (e.g. BRUTE_FORCE -> ACCOUNT_COMPROMISE) once it applies. */
  escalatesTo?: string;
  requiredTypes?: ProcedureItemType[];
  /** Include eligible actions after their checks, retaining their human-confirmed conditions. */
  conditionalActions?: boolean;
  stepOrder: number;
  phase: string;
  title: string;
  objective: string;
  items: RecommendationContextProcedureItem[];
  reason: string;
  expectedResult: string;
  decisionRef: string | null;
  responsibleRole: string;
  approvalRequired: boolean;
}

export interface RecommendationContextProcedureDecision {
  id: string;
  stepRef: number;
  question: string;
  options: { value: string; label: string; leadsTo: string }[];
}

export interface RecommendationContextContainmentProcedure {
  procedureCode: string;
  version: string;
  objective: string;
  strategy: string;
  steps: RecommendationContextProcedureStep[];
  decisions: RecommendationContextProcedureDecision[];
  /** Candidate Actions of the procedure with their conditions (containment.yaml). */
  candidateActions: { actionCode: string; condition: string | null; runbookRef: string | null }[];
  verification: { type: string; queryTemplate: string | null; successCriteria: string[]; additionalChecks: string[] };
}

/** A response-plan branch that opens another attack type's response because the evidence now supports it. */
export interface RecommendationContextTransition {
  from: string;
  to: string;
  /** The procedure step that carries the transition. */
  stepOrder: number;
  /** The evidence signals that made it apply. */
  because: string[];
}

/**
 * Knowledge retrieved for an incident that has no attack-specific playbook (RAG / IR / Defense / analyst-approved case
 * knowledge). Only items listed here can ground a dynamic response; the model never supplies its own.
 */
export interface RecommendationContextRetrievedKnowledge {
  ref: string;
  source: "IR_KNOWLEDGE" | "DEFENSE_KNOWLEDGE" | "CASE_KNOWLEDGE" | "THREAT_INTELLIGENCE";
  title: string;
  /** The response phase this knowledge supports. */
  phase: string;
  /** The control / investigation the knowledge recommends, in words an analyst can act on. */
  guidance: string;
  kind: "CHECK" | "MANUAL";
  requiresApproval: boolean;
}

/** An Action procedure the AI may actually recommend: applicable to the attack type AND its evidence is recorded. */
export const isRecommendable = (p: RecommendationContextActionProcedure): boolean => p.applicable !== false && p.evidence?.satisfied !== false;

/**
 * Values a response step may target (Task 10.3): IOCs linked to this cycle's evidence, IOCs an analyst
 * added to the investigation, and the affected hosts. Any other IOC (e.g. one the pipeline merely
 * extracted, like the reporting agent's own IP) is context only.
 */
export function targetableIocValues(context: Pick<RecommendationContextDto, "iocs" | "evidence">): Set<string> {
  const linked = new Set(context.evidence.flatMap((e) => e.iocValues));
  return new Set(context.iocs.filter((i) => linked.has(i.iocValue) || i.manual).map((i) => i.iocValue));
}

/** One step of an earlier Recommendation of this incident (any round, any status): the Action + target it proposed. */
export interface RecommendationContextPreviousStep {
  recommendationNumber: number;
  investigationNumber: number;
  actionCode: string;
  target: string;
}

export const stepKey = (actionCode: string, target: string): string => `${actionCode}|${target}`;

/**
 * Action + target pairs still open to a new Recommendation: recommendable Actions on their evidence-satisfying targets
 * that no earlier Recommendation of this incident proposed. A new Recommendation must contain at least one of them.
 * null = cannot tell (the context carries no evidence evaluation).
 */
export function noveltyHistory(context: Pick<RecommendationContextDto, "previousSteps"> & Partial<Pick<RecommendationContextDto, "spreadResponse" | "rehunt" | "investigationNumber">>): RecommendationContextPreviousStep[] {
  // A verified new host scope may need the same shared IOC blocked at another service.
  // Repeating a pair within that new cycle is still prohibited.
  const newScope = context.spreadResponse?.newHosts.length && context.rehunt?.spreadDetected && context.rehunt.result === "NOT_RESOLVED"
    && context.rehunt.verifiedInvestigationNumber === (context.investigationNumber ?? 0) - 1;
  return (context.previousSteps ?? []).filter(step => !newScope || step.investigationNumber === context.investigationNumber);
}

export function newStepOptions(context: Pick<RecommendationContextDto, "actionProcedures" | "previousSteps"> & Partial<Pick<RecommendationContextDto, "spreadResponse" | "rehunt" | "investigationNumber">>): { actionCode: string; target: string }[] | null {
  const procedures = context.actionProcedures ?? [];
  if (procedures.some((p) => !p.evidence)) return null;
  const used = new Set(noveltyHistory(context).map((s) => stepKey(s.actionCode, s.target)));
  return procedures
    .filter(isRecommendable)
    .flatMap((p) => p.evidence!.targets.map((target) => ({ actionCode: p.actionCode, target })))
    .filter((o) => !used.has(stepKey(o.actionCode, o.target)));
}

export interface RecommendationContextDto {
  rehunt?: import("../ports/IRecommendationContextRepository").RehuntContextRow | null;
  /** Matched spread policies; intersected with the published playbook and SOC guidance. */
  spreadResponse?: { policies: string[]; instructions: string[]; allowedActions: string[]; newHosts: string[]; uncoveredHosts: string[] } | null;
  incidentId: string;
  investigationNumber: number;
  incidentTitle: string;
  incidentStatus: string;
  incidentPriority: string;
  alertSeverity: string;
  iocs: RecommendationContextIoc[];
  mitreMappings: RecommendationContextMitreMapping[];
  /** Incident severity (analyst-validated when corrected) — the classification the Policy results below were
   * evaluated with. There is no risk score in the recommendation context. */
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  evidence: RecommendationContextEvidence[];
  /** Hosts named by this cycle's evidence — the only non-IOC values a step may target. */
  affectedHosts: string[];
  aiAnalysis: RecommendationContextAiAnalysis | null;
  availableActions: RecommendationContextAction[];
  availableRunbooks: RecommendationContextRunbook[];
  /** Task 10.3 — incident type of the selected playbook, or null when no incident-level playbook applies. */
  incidentType?: string | null;
  /** Knowledge attack type of the selected playbook (SSH_BRUTE_FORCE -> BRUTE_FORCE); null when none is known. */
  attackType?: string | null;
  playbook?: RecommendationContextPlaybook | null;
  /** Attack-specific containment procedure (YAML knowledge) — the primary strategy source; null when none exists. */
  containmentProcedure?: RecommendationContextContainmentProcedure | null;
  /** Evidence signals present in this incident (deriveEvidenceSignals) — what step gating and the validator use. */
  signals?: string[];
  /** Branches into another attack type's response that the present signals open (from the applicable procedure). */
  transitions?: RecommendationContextTransition[];
  /**
   * true when no attack-specific playbook applies (UNKNOWN_INCIDENT): the response is investigation-first and may
   * contain only CHECK steps, plus MANUAL steps grounded in retrievedKnowledge. No catalog Action is offered.
   */
  investigationOnly?: boolean;
  retrievedKnowledge?: RecommendationContextRetrievedKnowledge[];
  /** Actions the AI may expand (the playbook's allowedActions that exist, are enabled and are CONTAINMENT). */
  actionProcedures?: RecommendationContextActionProcedure[];
  /**
   * SOC response guidance in force (case > group policy > playbook default): the actions it allows (already applied
   * to playbook.allowedActions / actionProcedures) and the SOC's instruction for the Recommendation.
   */
  socGuidance?: { source: "CASE" | "GROUP" | "PLAYBOOK"; allowedActions: string[]; instructions: string | null } | null;
  /** Every step of this incident's earlier Recommendations. A new one must add at least one Action + target pair not
   * in this list (RecommendationValidator NO_NEW_STEP); repeating a pair alongside a new one is allowed. */
  previousSteps?: RecommendationContextPreviousStep[];
  /**
   * Subtype knowledge: the APPROVED plan (already policy-checked, deterministic). Present only for narration - the AI phrases a summary and
   * must not add, change or widen an action or target (SubtypeStepMapper reviews the answer).
   */
  subtypePlan?: { steps: { action: string; target: string | null; title: string }[]; missingInfo: string[] };
}
