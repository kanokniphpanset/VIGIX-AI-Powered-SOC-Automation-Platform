import { Severity, SEVERITIES } from "../policy/entities/PolicyEvaluationTypes";

/**
 * Normalises a stored severity-like value (incident.priority / alert.severity: "low".."critical", any case) to the
 * Policy Severity scale, or null when it is not one of the four levels.
 */
export function toSeverity(value: string | null | undefined): Severity | null {
  const s = (value ?? "").trim().toUpperCase();
  return (SEVERITIES as string[]).includes(s) ? (s as Severity) : null;
}

/**
 * The incident's severity as Policy sees it: the incident's own severity (incidents.priority — the alert severity at
 * creation, possibly validated / corrected by an analyst), else the alert severity, else MEDIUM (the pre-existing
 * default when nothing is known). Never derived from a risk score.
 */
export function incidentSeverity(ctx: { priority?: string | null; alertSeverity?: string | null } | null | undefined): Severity {
  return toSeverity(ctx?.priority) ?? toSeverity(ctx?.alertSeverity) ?? "MEDIUM";
}
