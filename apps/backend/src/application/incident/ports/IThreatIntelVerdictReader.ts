/**
 * The Threat Intelligence result the AI pipeline already recorded for an incident's indicators (output contract of the
 * latest completed AI job, `threatIntel.indicators`). Read-only and display-only: nothing here queries a provider,
 * re-scores an indicator or feeds the recommendation context.
 */
export interface ThreatIntelVerdict {
  iocType: string;
  iocValue: string;
  /** MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN — exactly as the pipeline recorded it. */
  verdict: string | null;
  confidence: number | null;
  /** Providers that answered and how (e.g. misp · SUCCESS · LIVE). */
  providers: { provider: string; status: string; source: string | null }[];
  evidence: { provider: string; summary: string | null; reference: string | null }[];
  queriedAt: string | null;
  executionId: string | null;
}

export interface IThreatIntelVerdictReader {
  latestVerdicts(incidentId: string): Promise<ThreatIntelVerdict[]>;
}
