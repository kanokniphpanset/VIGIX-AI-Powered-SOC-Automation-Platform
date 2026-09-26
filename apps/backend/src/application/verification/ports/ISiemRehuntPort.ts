/**
 * ISiemRehuntPort — asks a SIEM "did the threat recur after containment?"
 * and returns EVIDENCE ONLY, normalized into VIGIX's own shape. It never
 * decides RESOLVED / NOT_RESOLVED (that stays in CreateVerificationUseCase)
 * and it never returns raw vendor JSON as its model.
 *
 * Separate from ISiemAdapter on purpose: ISiemAdapter is the alert-INGEST
 * contract every SIEM vendor implements (Wazuh, Splunk, Defender, ELK);
 * widening it would force every one of them to implement re-hunt too.
 */

export interface RehuntIoc {
  type: string;
  value: string;
}

export interface RehuntRuleSignature {
  id?: string;
  description?: string;
}

export interface RehuntQuery {
  incidentId: string;
  responseId: string;
  /** Hosts the incident originally involved (agent names). */
  hosts: string[];
  /** Indicators to look for anywhere in the environment. */
  iocs: RehuntIoc[];
  /** The original detection's rule, used together with `hosts` to find the same behaviour recurring. */
  rule?: RehuntRuleSignature;
  /** Events strictly after containment completed. */
  timeRange: { start: Date; end: Date };
  /** The incident's investigation cycle being verified (1-based). Informational for a real SIEM; a fixture-backed
   * provider uses it to pick the matching round. */
  investigationNumber?: number;
}

export interface RehuntEvent {
  id: string;
  timestamp: string;
  host: string | null;
  agentId: string | null;
  ruleId: string | null;
  ruleLevel: number | null;
  ruleDescription: string | null;
  /** True when this event matched one of the IOCs (as opposed to only the host+rule signature). */
  matchedIoc: boolean;
  /** Which queried IOC values matched, identified by per-IOC named queries for Wazuh.
   * Used to carry those IOCs into the new investigation cycle. */
  matchedIocValues?: string[];
}

export interface RehuntResult {
  /** WAZUH_INDEXER = real Wazuh Indexer; MOCK_REHUNT = deterministic fixture provider (dev/test only). */
  source: "WAZUH_INDEXER" | "MOCK_REHUNT";
  index: string;
  /** The exact query body that was run (contains no credentials). */
  query: string;
  timeRange: { start: string; end: string };
  matchingEvents: number;
  affectedHosts: string[];
  iocRecurrence: boolean;
  spreadDetected: boolean;
  /** Evidence-derived: no matching activity after containment. VIGIX Verification still makes the final call. */
  threatContained: boolean;
  events: RehuntEvent[];
  /** True when more events matched than `events` carries. */
  truncated: boolean;
  /**
   * IOC categories left out of the search because the index has none of their fields (e.g. no DNS data at all).
   * They were NOT searched — never read them as NO_MATCH. Optional: providers that search everything omit it.
   */
  skippedIocTypes?: string[];
  /** The IOCs the query actually searched. */
  searchedIocs?: { type: string; value: string }[];
  /** The IOCs left out, with the reason. */
  skippedIocs?: { type: string; value: string; reason: string }[];
}

/** Every failure is an error, never an empty result: a re-hunt that did not run proves nothing about containment. */
export type RehuntErrorCode = "NOT_CONFIGURED" | "INSUFFICIENT_CRITERIA" | "UNREACHABLE" | "QUERY_FAILED" | "TIMEOUT";

export class RehuntError extends Error {
  constructor(
    public readonly code: RehuntErrorCode,
    message: string
  ) {
    super(message);
  }
}

export interface RehuntHealth {
  configured: boolean;
  reachable: boolean;
  clusterStatus?: string;
  indexPattern: string;
  alertIndices?: number;
  error?: string;
}

export interface ISiemRehuntPort {
  isConfigured(): boolean;
  health(): Promise<RehuntHealth>;
  rehunt(query: RehuntQuery): Promise<RehuntResult>;
}
