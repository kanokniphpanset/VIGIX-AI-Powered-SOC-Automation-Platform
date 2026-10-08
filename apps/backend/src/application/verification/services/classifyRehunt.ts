import {
  RehuntClassification, RehuntCorrelationReason, RehuntCoverage, RehuntEvent, RehuntQuery,
} from "../ports/ISiemRehuntPort";

/**
 * classifyRehunt - pure re-hunt semantics (Phase 2D). Given the events a search found and what the search could see, decide what
 * may and may not be claimed. Three rules it exists to enforce:
 *
 *   same IOC            != spread        an IOC value on another agent is only "spread" when a stated correlation reason ties the
 *                                        event to the original incident; otherwise it is UNCORROBORATED_MATCH (inconclusive)
 *   file deleted        != recurrence    deleting the searched artifact is CLEANUP, reported but never counted as activity
 *   no matching alert   != contained     "not observed" needs complete coverage, else INCOMPLETE
 *
 * No I/O, no clock. Deterministic: the same inputs always give the same class.
 */

/**
 * Rule groups that every alert of a log source (or every harness / fixture rule) carries; sharing one says nothing about
 * "same kind of activity". vigix_eval / vigix_custom are the provenance markers of the evaluation harness and the mock fixtures.
 */
export const GENERIC_RULE_GROUPS: readonly string[] = ["syslog", "windows", "ossec", "linux", "local", "wazuh", "web", "accesslog", "sysmon", "windows_security", "pam", "vigix_eval", "vigix_custom"];

export interface ClassifyInput {
  query: Pick<RehuntQuery, "hosts" | "agentIds" | "rule" | "correlation">;
  /** Every event that was fetched (may be fewer than `totalMatched` when the cap was reached). */
  events: RehuntEvent[];
  totalMatched: number;
  /** Fetched all matches (not capped). */
  complete: boolean;
  skippedIocTypes: string[];
  coverage: RehuntCoverage;
}

export interface ClassifyOutput {
  classification: RehuntClassification;
  /** Events with scope / kind / correlation filled in. */
  events: RehuntEvent[];
  activityCount: number;
  ignoredEvents: number;
  matchedHosts: string[];
  correlationReasons: Partial<Record<RehuntCorrelationReason, number>>;
  /** Why an absence claim was refused (empty unless classification is INCOMPLETE with no matches). */
  incompleteReasons: string[];
}

const lower = (s: string | null | undefined) => (s ?? "").trim().toLowerCase();

export function correlationReasons(query: ClassifyInput["query"], e: RehuntEvent): RehuntCorrelationReason[] {
  const reasons: RehuntCorrelationReason[] = [];
  if (query.rule?.id && e.ruleId === query.rule.id) reasons.push("SAME_RULE");
  const originalGroups = (query.rule?.groups ?? []).map(lower).filter((g) => g && !GENERIC_RULE_GROUPS.includes(g));
  if ((e.ruleGroups ?? []).map(lower).some((g) => originalGroups.includes(g))) reasons.push("SHARED_RULE_GROUP");
  if (e.processGuid && (query.correlation?.processGuids ?? []).some((g) => lower(g) === lower(e.processGuid))) reasons.push("SAME_PROCESS_GUID");
  if (e.filePath && e.fileOperation !== "deleted" && (query.correlation?.filePaths ?? []).includes(e.filePath)) reasons.push("SAME_FILE_PATH");
  return reasons;
}

export function classifyRehunt(input: ClassifyInput): ClassifyOutput {
  const { query } = input;
  const hostNames = new Set(query.hosts.map(lower));
  const agentIds = new Set((query.agentIds ?? []).map(lower));
  const inScope = (e: RehuntEvent) => (e.agentId && agentIds.has(lower(e.agentId))) || (!!e.host && hostNames.has(lower(e.host)));

  const events = input.events.map((e): RehuntEvent => {
    const reasons = e.matchedIoc ? correlationReasons(query, e) : [];
    return {
      ...e,
      kind: e.fileOperation === "deleted" ? "CLEANUP" : "ACTIVITY",
      inScope: !!inScope(e),
      correlation: { corroborated: reasons.length > 0, reasons },
    };
  });

  const activity = events.filter((e) => e.kind === "ACTIVITY");
  const corroborated = activity.filter((e) => e.correlation?.corroborated);
  const newScope = corroborated.filter((e) => !e.inScope);
  const inScopeHits = corroborated.filter((e) => e.inScope);
  const uncorroborated = activity.filter((e) => !e.correlation?.corroborated);

  const reasonCounts: Partial<Record<RehuntCorrelationReason, number>> = {};
  for (const e of corroborated) for (const r of e.correlation!.reasons) reasonCounts[r] = (reasonCounts[r] ?? 0) + 1;
  const matchedHosts = [...new Set(corroborated.map((e) => e.host).filter((h): h is string => !!h))];

  const incompleteReasons: string[] = [];
  if (!input.complete) incompleteReasons.push(`only ${input.events.length} of ${input.totalMatched} matches were fetched (result cap)`);
  if (input.skippedIocTypes.length) incompleteReasons.push(`IOC types not searchable in this index: ${input.skippedIocTypes.join(", ")}`);
  if (!input.coverage.complete) incompleteReasons.push(...input.coverage.gaps);

  let classification: RehuntClassification;
  if (newScope.length > 0) classification = "NEW_SCOPE_ACTIVITY";
  else if (inScopeHits.length > 0) classification = "IN_SCOPE_ACTIVITY";
  else if (uncorroborated.length > 0) classification = "UNCORROBORATED_MATCH";
  else classification = incompleteReasons.length === 0 ? "NO_MATCH_COVERED" : "INCOMPLETE";

  return {
    classification,
    events,
    activityCount: input.complete ? activity.length : input.totalMatched,
    ignoredEvents: events.length - activity.length,
    matchedHosts,
    correlationReasons: reasonCounts,
    incompleteReasons: classification === "INCOMPLETE" ? incompleteReasons : [],
  };
}
