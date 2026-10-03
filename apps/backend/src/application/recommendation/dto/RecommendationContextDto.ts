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
export function newStepOptions(context: Pick<RecommendationContextDto, "actionProcedures" | "previousSteps">): { actionCode: string; target: string }[] | null {
  const procedures = context.actionProcedures ?? [];
  if (procedures.some((p) => !p.evidence)) return null;
  const used = new Set((context.previousSteps ?? []).map((s) => stepKey(s.actionCode, s.target)));
  return procedures
    .filter(isRecommendable)
    .flatMap((p) => p.evidence!.targets.map((target) => ({ actionCode: p.actionCode, target })))
    .filter((o) => !used.has(stepKey(o.actionCode, o.target)));
}

export interface RecommendationContextDto {
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
}
