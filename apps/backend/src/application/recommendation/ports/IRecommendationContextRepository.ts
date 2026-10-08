import { AnalysisSource } from "../../../domain/ai/analysisSource";
import type { TicketRecord } from "../../../domain/subtype/actionState";
import type { SubtypeEvidenceRow } from "../../subtype/factBuilder";
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
  /** Role of an IP IOC in the alert that raised the incident (data.srcip -> source, data.dstip -> destination). */
  networkRole?: "source" | "destination";
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
  getRehuntContext?(incidentId: string, tenantId: string, investigationNumber: number): Promise<RehuntContextRow | null>;
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
  /** Action + target of every step of the incident's earlier Recommendations (all rounds, any status). */
  getPreviousRecommendationSteps?(incidentId: string, tenantId: string): Promise<PreviousRecommendationStepRow[]>;
  /** Subtype knowledge: this cycle's evidence WITH structuredData (Evidence Contract v2 / analyst assertions), citation ids E<n> as in getEvidence. */
  getSubtypeEvidence?(incidentId: string, tenantId: string, investigationNumber: number): Promise<SubtypeEvidenceRow[]>;
  /** Subtype knowledge: every Response Ticket of the incident with its action, target, status and IR result (action state across rounds). */
  getTicketHistory?(incidentId: string, tenantId: string): Promise<TicketRecord[]>;
}

export interface PreviousRecommendationStepRow {
  recommendationNumber: number;
  investigationNumber: number;
  actionCode: string;
  target: string;
}

/** Re-hunt of the immediately preceding cycle; manual entries cannot activate spread response. */
export interface RehuntContextRow {
  verificationId: string;
  verifiedInvestigationNumber: number;
  source: "WAZUH_INDEXER" | "MOCK_REHUNT";
  result: "RESOLVED" | "NOT_RESOLVED";
  spreadDetected: boolean;
  matchingEvents: number;
  originalHosts: string[];
  affectedHosts: string[];
  newHosts: string[];
  truncated: boolean;
  /** Re-hunt classification (IN_SCOPE_ACTIVITY | NEW_SCOPE_ACTIVITY | NO_MATCH_COVERED ...) when the provider correlates. */
  classification?: string | null;
  /** true only when the search could see everything it needed (agents, archives, window); absence is claimable only then. */
  coverageComplete?: boolean | null;
  verifiedAt?: Date | null;
}
