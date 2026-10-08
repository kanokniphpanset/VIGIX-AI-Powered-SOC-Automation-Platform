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
  /** The original detection's rule groups: lets a re-hunt tell "same kind of activity" from an unrelated rule. */
  groups?: string[];
}

/** Identifiers of the ORIGINAL evidence that a later event can be correlated by (beyond sharing an IOC value). */
export interface RehuntCorrelationKeys {
  processGuids?: string[];
  filePaths?: string[];
}

/** Why an event was tied to the original incident. An IOC value alone is never a reason. */
export type RehuntCorrelationReason = "SAME_RULE" | "SHARED_RULE_GROUP" | "SAME_PROCESS_GUID" | "SAME_FILE_PATH";

/**
 * What the re-hunt concluded. NO_MATCH_COVERED is the only class that may support "not seen again", and only for events that
 * raise a Wazuh rule (archives are off). INCOMPLETE and UNCORROBORATED_MATCH are inconclusive: they never create a verification.
 */
export type RehuntClassification = "IN_SCOPE_ACTIVITY" | "NEW_SCOPE_ACTIVITY" | "UNCORROBORATED_MATCH" | "NO_MATCH_COVERED" | "INCOMPLETE";

export type RehuntEventKind = "ACTIVITY" | "CLEANUP";

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
  /** Stable Wazuh agent ids of `hosts` (names are reused across container restarts). */
  agentIds?: string[];
  /**
   * The agents the incident is actually about (the alert's own agent). `hosts` can also hold a response TARGET that merely looks like a
   * host (a file path, an account name ...). Coverage is REQUIRED only for these; any other host is checked only if it turns out to be an
   * agent with status snapshots. Absent = every entry of `hosts` is treated as an agent.
   */
  scopeAgents?: string[];
  /** Process / file identifiers of the original alert, used to corroborate a match. */
  correlation?: RehuntCorrelationKeys;
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

  // ---- set by the correlating provider only (all optional: the plain provider and the mock leave them out)
  /** Indexer index of the document (with `id` this is the full document reference). */
  index?: string;
  /** Wazuh alert id (the `id` field) - the dedupe key. */
  alertId?: string | null;
  ruleGroups?: string[];
  /** MOCK_FIXTURE / HARNESS_GENERATED / REAL_TELEMETRY / UNKNOWN_ORIGIN, from the same markers as Evidence Contract v2. */
  provenanceClass?: string;
  /** CLEANUP = the artifact was deleted (FIM `deleted`): not a recurrence. */
  kind?: RehuntEventKind;
  inScope?: boolean;
  processGuid?: string | null;
  filePath?: string | null;
  fileOperation?: string | null;
  correlation?: { corroborated: boolean; reasons: RehuntCorrelationReason[] };
  /** Indexer sort values of this hit (pagination cursor). */
  sortValues?: unknown[];
}

export interface RehuntAgentCoverage {
  name: string;
  /** From the hourly wazuh-monitoring snapshots in/just before the window. */
  status: "ACTIVE_THROUGHOUT" | "DISCONNECTED_IN_WINDOW" | "UNKNOWN";
  nonActiveSnapshots: number;
  lastSnapshotAt: string | null;
}

/** What the search could and could not see. `complete` is the precondition for any "not observed" claim. */
export interface RehuntCoverage {
  sources: { alerts: "AVAILABLE"; archives: "AVAILABLE" | "NOT_AVAILABLE" | "UNKNOWN" };
  indexRange: { min: string | null; max: string | null } | null;
  /** The index holds data from before the window starts (null = could not be determined). */
  windowCoveredByIndex: boolean | null;
  agents: RehuntAgentCoverage[];
  complete: boolean;
  /** Why it is not complete (empty when complete). */
  gaps: string[];
  /** Always true for what cannot be fixed by the search itself, e.g. "archives are off: only events that raised a rule can be found". */
  limitations: string[];
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

  // ---- set by the correlating provider only
  classification?: RehuntClassification;
  /** Documents that matched an IOC value at all (matchingEvents counts activity only, cleanup excluded). */
  totalMatched?: number;
  /** Events that matched but are not recurrence (e.g. the searched file being deleted). */
  ignoredEvents?: number;
  /** Per-reason counts over the corroborated events. */
  correlationReasons?: Partial<Record<RehuntCorrelationReason, number>>;
  /** Agents (name) with corroborated activity - affectedHosts lists these, not every agent that merely matched. */
  matchedHosts?: string[];
  coverage?: RehuntCoverage;
  pagination?: { pageSize: number; pagesFetched: number; fetched: number; total: number; cap: number; complete: boolean };
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
