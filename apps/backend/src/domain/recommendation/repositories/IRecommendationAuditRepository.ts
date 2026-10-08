/**
 * Internal audit of the subtype-knowledge evaluation behind a Recommendation (subtype/scenario, evidence refs, policy decisions,
 * resolved targets, action/runbook versions, ordering reasons, missing fields, authority/capability checks). Stored SEPARATELY from
 * the Recommendation and its user-facing text; only returned by an explicit audit endpoint.
 */
export type SubtypeAuditMode = "SHADOW" | "ENFORCE" | "ENFORCE_FALLBACK";

export interface RecommendationAuditRecord {
  tenantId: string;
  incidentId: string;
  /** null when no recommendation was persisted (nothing eligible / generation failed). */
  recommendationId: string | null;
  investigationNumber: number;
  mode: SubtypeAuditMode;
  knowledgeVersion: string;
  knowledgeStatus: string;
  audit: unknown;
}

export interface IRecommendationAuditRepository {
  save(record: RecommendationAuditRecord): Promise<void>;
  findByRecommendation(recommendationId: string, tenantId: string): Promise<(RecommendationAuditRecord & { createdAt: Date }) | null>;
  /** Latest stored evaluation of an incident (read-only; used by the Recommendation Preview to reuse a stored shadow result). */
  findLatestByIncident?(incidentId: string, tenantId: string): Promise<(RecommendationAuditRecord & { createdAt: Date }) | null>;
}
