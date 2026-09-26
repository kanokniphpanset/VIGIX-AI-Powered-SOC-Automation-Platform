import { AnalysisSource } from "../../../domain/ai/analysisSource";
export interface IncidentContextRow {
  incidentId: string;
  investigationNumber: number;
  title: string;
  status: string;
  /** The incident SEVERITY (low | medium | high | critical). Starts as the alert severity; an analyst may validate /
   * correct it (ValidateIncidentSeverity). This is the Policy's primary classification input — see incidentSeverity(). */
  priority: string;
  alertSeverity: string;
}

export interface IocContextRow {
  iocType: string;
  iocValue: string;
  source: string;
  reputationScore: number | null;
  /** Added by an analyst (createdBy set, not "system") rather than extracted by the pipeline. */
  manual?: boolean;
  /** Provenance (display / audit only — not part of the recommendation prompt). */
  id?: string;
  createdBy?: string | null;
  createdAt?: Date;
  /** Related-alert evidence: the other Wazuh alert the SOC observed this indicator in. */
  sourceAlertId?: string | null;
  sourceExternalAlertId?: string | null;
  addedReason?: string | null;
}

export interface MitreMappingContextRow {
  techniqueId: string;
  tactic: string;
  confidence: number | null;
}

export interface EvidenceContextRow {
  type: string;
  source: string;
  origin: string;
  title: string;
  timestamp: Date;
  host: string | null;
  ruleId: string | null;
  iocValues: string[];
}

export interface AiAnalysisContextRow {
  summary: string;
  keyFindings: string[];
  /**
   * Post-generation grounding check (domain/ai/aiGrounding.ts): every concrete indicator the text names must exist in
   * the incident's alerts / evidence / IOCs. UNGROUNDED analysis is shown for review but is NOT trusted input.
   */
  grounding: { status: "GROUNDED" | "UNGROUNDED"; ungrounded: { kind: string; value: string }[] };
  /** Always "LLM" for rows returned by getLatestAiAnalysis (see domain/ai/analysisSource.ts). */
  source?: AnalysisSource;
  model?: string | null;
  generatedAt?: Date;
}

/** The most recent analysis run of any source — lets the UI say when a newer run failed or was a legacy fallback. */
export interface AnalysisRunRow {
  source: AnalysisSource;
  generatedAt: Date;
}

/**
 * IRecommendationContextRepository — a read-only, composite query port used
 * ONLY by RecommendationContextBuilder. Deliberately separate from
 * IIncidentRepository (which owns the Incident aggregate's mutations):
 * this exists purely to assemble the facts already in Postgres
 * (Incident+Alert, ThreatIntelIoc, MitreMapping) into the Recommendation
 * Context — it never mutates anything.
 */
export interface IRecommendationContextRepository {
  getIncidentContext(incidentId: string, tenantId: string): Promise<IncidentContextRow | null>;
  /** IOCs of the incident; with investigationNumber, only that investigation cycle's IOCs. */
  getIocs(incidentId: string, investigationNumber?: number): Promise<IocContextRow[]>;
  getMitreMappings(incidentId: string): Promise<MitreMappingContextRow[]>;
  /** Evidence of one investigation cycle, with the IOC values linked to each row. */
  getEvidence(incidentId: string, investigationNumber: number): Promise<EvidenceContextRow[]>;
  /** LlmAnalystAgent output of the incident's most recent AI pipeline run, if any. */
  /** The latest analysis actually produced by the LLM; fallback / failed / unverified legacy rows are skipped. */
  getLatestAiAnalysis(incidentId: string): Promise<AiAnalysisContextRow | null>;
  getLatestAnalysisRun?(incidentId: string): Promise<AnalysisRunRow | null>;
}
