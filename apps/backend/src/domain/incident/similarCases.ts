/**
 * Similar past cases — pure, deterministic scoring of CLOSED incidents against one incident (no I/O, no AI).
 *
 * A case's fingerprint is facts already stored on it: its threat-intel IOCs, the Wazuh rule ids / monitored hosts of its
 * alerts, and its MITRE techniques (incident mappings + the alerts' rule.mitre ids). Two cases are compared by what
 * they share:
 *   SAME_IOC        3 per shared indicator
 *   SAME_RULE       2 per shared Wazuh rule id
 *   SAME_TECHNIQUE  2 per shared MITRE technique
 *   SAME_HOST       1 per shared host
 * Each kind counts at most MAX_PER_KIND shared values, so one noisy kind (e.g. many IOCs) cannot drown the others.
 * A shared host alone never makes a case similar (same machine, different attack); at least one IOC, rule or
 * technique must match. Every match is returned with its values, so the analyst sees WHY a case was suggested.
 * Loopback / unspecified addresses (127.x, ::1, 0.0.0.0) are not indicators of anything and never count as a shared IOC.
 */
export type SimilarityKind = "SAME_IOC" | "SAME_RULE" | "SAME_TECHNIQUE" | "SAME_HOST";

export const SIMILARITY_WEIGHTS: Record<SimilarityKind, number> = { SAME_IOC: 3, SAME_RULE: 2, SAME_TECHNIQUE: 2, SAME_HOST: 1 };
export const MAX_PER_KIND = 3;
export const SIMILAR_CASES_LIMIT = 5;

export interface CaseFingerprint {
  /** "TYPE:value", value lower-cased (see iocKey). */
  iocs: string[];
  ruleIds: string[];
  techniques: string[];
  hosts: string[];
}

export interface SimilarityReason {
  kind: SimilarityKind;
  values: string[];
}

export const iocKey = (type: string, value: string) => `${type.toUpperCase()}:${value.trim().toLowerCase()}`;

/** IOC keys that say nothing about an attack (loopback / unspecified addresses). */
export const isNoiseIoc = (key: string) => /^IPV[46]:(127\.|::1$|0\.0\.0\.0$|::$)/.test(key);

const norm = (xs: string[], lower = false) =>
  new Set(xs.map((x) => (lower ? x.trim().toLowerCase() : x.trim())).filter(Boolean));

function shared(a: string[], b: string[], lower = false): string[] {
  const right = norm(b, lower);
  return [...norm(a, lower)].filter((x) => right.has(x)).sort();
}

/** Score + reasons of `candidate` against `target`; score 0 (no reasons) when not similar. */
export function similarity(target: CaseFingerprint, candidate: CaseFingerprint): { score: number; reasons: SimilarityReason[] } {
  const matches: [SimilarityKind, string[]][] = [
    ["SAME_IOC", shared(target.iocs, candidate.iocs).filter((k) => !isNoiseIoc(k))], // already normalised by iocKey
    ["SAME_RULE", shared(target.ruleIds, candidate.ruleIds)],
    ["SAME_TECHNIQUE", shared(target.techniques.map((t) => t.toUpperCase()), candidate.techniques.map((t) => t.toUpperCase()))],
    ["SAME_HOST", shared(target.hosts, candidate.hosts, true)],
  ];
  const reasons = matches.filter(([, v]) => v.length).map(([kind, values]) => ({ kind, values }));
  if (!reasons.some((r) => r.kind !== "SAME_HOST")) return { score: 0, reasons: [] };
  const score = reasons.reduce((s, r) => s + SIMILARITY_WEIGHTS[r.kind] * Math.min(r.values.length, MAX_PER_KIND), 0);
  return { score, reasons };
}

/**
 * The `limit` most similar candidates (score > 0), best first; ties go to the most recently closed case.
 * The target itself is never returned.
 */
export function rankSimilarCases<C extends CaseFingerprint & { id: string; closedAt: string | null }>(
  target: CaseFingerprint & { id: string },
  candidates: C[],
  limit = SIMILAR_CASES_LIMIT
): (C & { score: number; reasons: SimilarityReason[] })[] {
  return candidates
    .filter((c) => c.id !== target.id)
    .map((c) => ({ ...c, ...similarity(target, c) }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score || (b.closedAt ?? "").localeCompare(a.closedAt ?? ""))
    .slice(0, limit);
}
