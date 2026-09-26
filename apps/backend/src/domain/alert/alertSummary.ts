/**
 * alertSummary — pure read helpers over a stored SIEM alert's raw (Wazuh-format) payload, used by the Alert
 * Inbox / Alert Detail / Set Group read models. No I/O, no inference: every field is read from the payload
 * as received, and absent fields stay null / empty.
 */
export interface AlertSummary {
  ruleId: string | null;
  ruleDescription: string | null;
  ruleLevel: number | null;
  mitreTechniques: string[];
  sourceIp: string | null;
  destinationIp: string | null;
  /** The monitored host the alert is about (Wazuh agent name). */
  host: string | null;
  agentIp: string | null;
  user: string | null;
}

function obj(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : typeof v === "number" ? String(v) : null;
}

export function summarizeAlert(rawPayload: unknown): AlertSummary {
  const p = obj(rawPayload) ?? {};
  const rule = obj(p.rule) ?? {};
  const agent = obj(p.agent) ?? {};
  const data = obj(p.data) ?? {};
  const win = obj(obj(data.win)?.eventdata) ?? {};
  const mitreIds = obj(rule.mitre)?.id;
  const level = typeof rule.level === "number" ? rule.level : Number(rule.level);
  return {
    ruleId: str(rule.id),
    ruleDescription: str(rule.description),
    ruleLevel: Number.isFinite(level) ? level : null,
    mitreTechniques: Array.isArray(mitreIds) ? mitreIds.map(str).filter((t): t is string => !!t) : [],
    sourceIp: str(data.srcip),
    destinationIp: str(data.dstip),
    host: str(agent.name),
    agentIp: str(agent.ip),
    user: str(data.dstuser) ?? str(data.srcuser) ?? str(win.targetUserName) ?? str(win.user),
  };
}

export type RelatedReason = "SAME_SOURCE_IP" | "SAME_TARGET_HOST" | "SAME_TECHNIQUE" | "SAME_RULE" | "SAME_TIME_WINDOW";

/** Alerts closer together than this also get the SAME_TIME_WINDOW reason. */
export const RELATED_TIME_WINDOW_MS = 60 * 60 * 1000;

/**
 * Why alert `b` looks related to alert `a` — facts only. A suggestion is made when the alerts share the source IP,
 * or share the target host AND either the technique or the rule; the time window alone never relates two alerts.
 * The analyst decides (Set Group); nothing is merged automatically.
 */
export function relatedReasons(
  a: { summary: AlertSummary; receivedAt: Date },
  b: { summary: AlertSummary; receivedAt: Date }
): RelatedReason[] {
  const reasons: RelatedReason[] = [];
  if (a.summary.sourceIp && a.summary.sourceIp === b.summary.sourceIp) reasons.push("SAME_SOURCE_IP");
  if (a.summary.host && a.summary.host === b.summary.host) reasons.push("SAME_TARGET_HOST");
  if (a.summary.mitreTechniques.some((t) => b.summary.mitreTechniques.includes(t))) reasons.push("SAME_TECHNIQUE");
  if (a.summary.ruleId && a.summary.ruleId === b.summary.ruleId) reasons.push("SAME_RULE");
  const related =
    reasons.includes("SAME_SOURCE_IP") ||
    (reasons.includes("SAME_TARGET_HOST") && (reasons.includes("SAME_TECHNIQUE") || reasons.includes("SAME_RULE")));
  if (!related) return [];
  if (Math.abs(a.receivedAt.getTime() - b.receivedAt.getTime()) <= RELATED_TIME_WINDOW_MS) reasons.push("SAME_TIME_WINDOW");
  return reasons;
}
