/**
 * Alert Inbox — SOC review of Wazuh alerts (pure, no I/O). One canonical workflow shared by the backend and the frontend.
 *
 * Severity comes from the Wazuh rule level (deterministic mapping at ingestion); AI never sets or changes it.
 *   LOW       stored for the record only — never enters the SOC workflow and never opens an incident
 *   MEDIUM    waits in the Alert Inbox for SOC review: close it (False positive / Informational, reason required)
 *             or create an incident from it
 *   HIGH/CRIT open an incident automatically at ingestion (Policy INTAKE); SOC investigates the incident
 *
 * Stored state (alerts.workflow_state):
 *   NEW         -> waiting for SOC review
 *   TRIAGED     -> decided: closed (FALSE_POSITIVE / INFORMATIONAL) or escalated to an incident
 *   MONITORING  -> legacy (retired MONITOR decision): still open and decidable; returns to NEW when its review date passes
 *   IN_TRIAGE   -> history only (retired alert claiming); treated exactly like NEW
 * There is no alert owner and no claim: any SOC analyst may decide an open alert, and the decision is committed with a
 * conditional write, so two analysts can never both decide the same alert.
 *
 * Display state (derived, never stored): NEEDS_REVIEW | MONITORING | CLOSED | IN_INCIDENT.
 */

export type AlertWorkflowState = "NEW" | "IN_TRIAGE" | "MONITORING" | "TRIAGED";
export const ALERT_WORKFLOW_STATES: AlertWorkflowState[] = ["NEW", "IN_TRIAGE", "MONITORING", "TRIAGED"];

/** States a SOC decision can be committed from (IN_TRIAGE / MONITORING: legacy rows, reviewed like NEW). */
export const OPEN_WORKFLOW_STATES: AlertWorkflowState[] = ["NEW", "IN_TRIAGE", "MONITORING"];

/** Only these severities enter the SOC workflow (Alert Inbox). LOW alerts are stored but never shown or triaged. */
export const SOC_WORKFLOW_SEVERITIES = ["medium", "high", "critical"] as const;
export const inSocWorkflow = (severity: string) => (SOC_WORKFLOW_SEVERITIES as readonly string[]).includes(severity.toLowerCase());
/** Deterministic fallback when Policy INTAKE is unavailable: HIGH / CRITICAL open an incident automatically. */
export const AUTO_INCIDENT_SEVERITIES = ["high", "critical"] as const;
export const autoIncidentBySeverity = (severity: string) => (AUTO_INCIDENT_SEVERITIES as readonly string[]).includes(severity.toLowerCase());

export type AlertDisplayState = "NEEDS_REVIEW" | "MONITORING" | "CLOSED" | "IN_INCIDENT";

/** Alert Inbox status filter -> stored states (+ incident link). */
export type InboxStatus = "needs-review" | "in-incident" | "closed" | "all";
export const INBOX_STATUSES: InboxStatus[] = ["needs-review", "in-incident", "closed", "all"];
export const isInboxStatus = (v: unknown): v is InboxStatus => typeof v === "string" && (INBOX_STATUSES as string[]).includes(v);

export function displayState(a: { workflowState: string | null; incidentId: string | null }): AlertDisplayState {
  if (a.incidentId) return "IN_INCIDENT";
  switch (a.workflowState) {
    case "MONITORING":
      return "MONITORING";
    case "TRIAGED":
      return "CLOSED";
    default:
      return "NEEDS_REVIEW";
  }
}

/** SOC decisions on an open alert. Closing is for MEDIUM alerts; any open alert can become an incident. */
export type TriageDecision = "FALSE_POSITIVE" | "INFORMATIONAL" | "CREATE_INCIDENT";
export const TRIAGE_DECISIONS: TriageDecision[] = ["FALSE_POSITIVE", "INFORMATIONAL", "CREATE_INCIDENT"];

export type TriageInputError = "REASON_REQUIRED";

/** FALSE_POSITIVE / INFORMATIONAL need a reason. CREATE_INCIDENT keeps the Wazuh severity, so nothing else is required. */
export function validateTriageInput(input: { decision: TriageDecision; reason: string | null | undefined }): TriageInputError | null {
  if (input.decision === "CREATE_INCIDENT") return null;
  return input.reason?.trim() ? null : "REASON_REQUIRED";
}

// ---------------------------------------------------------------- Triage SLA
export type SlaMinutesBySeverity = Partial<Record<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL", number>>;
export type SlaStatus = "ON_TRACK" | "DUE_SOON" | "BREACHED" | "MET" | "MISSED";

/**
 * The review clock starts when the alert entered the queue: received_at, or review_at when a (legacy) monitored alert
 * came back for review. The target minutes come from Policy (TRIAGE_SLA); no target -> no SLA (never a made-up one).
 */
export function slaDueAt(a: { severity: string; receivedAt: Date; reviewAt: Date | null; workflowState: string | null }, minutes: SlaMinutesBySeverity): Date | null {
  const target = minutes[a.severity.toUpperCase() as keyof SlaMinutesBySeverity];
  if (!target) return null;
  const start = (a.workflowState === "NEW" || a.workflowState === "IN_TRIAGE") && a.reviewAt ? a.reviewAt : a.receivedAt;
  return new Date(start.getTime() + target * 60_000);
}

/**
 * Open alerts: ON_TRACK / DUE_SOON (last 25% of the target) / BREACHED. Decided alerts: MET / MISSED by when they
 * were closed or escalated. Monitoring alerts wait on review_at instead (null).
 */
export function slaStatus(
  a: { workflowState: string | null; closedAt: Date | null; severity: string },
  dueAt: Date | null,
  minutes: SlaMinutesBySeverity,
  now: Date
): SlaStatus | null {
  if (!dueAt) return null;
  if (a.workflowState === "MONITORING") return null;
  if (a.workflowState === "TRIAGED") return a.closedAt ? (a.closedAt.getTime() <= dueAt.getTime() ? "MET" : "MISSED") : null;
  const remaining = dueAt.getTime() - now.getTime();
  if (remaining < 0) return "BREACHED";
  const target = (minutes[a.severity.toUpperCase() as keyof SlaMinutesBySeverity] ?? 0) * 60_000;
  return remaining <= target * 0.25 ? "DUE_SOON" : "ON_TRACK";
}

/** Queue ordering (server-side). urgency = SLA due soonest, then severity, then oldest. */
export type InboxSort = "urgency" | "severity" | "oldest" | "newest";
export const INBOX_SORTS: InboxSort[] = ["urgency", "severity", "oldest", "newest"];
export const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
