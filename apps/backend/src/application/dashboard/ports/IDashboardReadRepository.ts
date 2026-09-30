/** Read-only aggregates for the operations dashboard (one tenant). Counts only — no mutation, no inference. */
export interface DashboardCounts {
  alerts: {
    total: number;
    last24h: number;
    unlinked: number;
    bySeverity: Record<string, number>;
    /** One row per UTC day, oldest first, for the last `days` days (zero-filled). */
    daily: { date: string; critical: number; high: number; medium: number; low: number }[];
  };
  incidents: {
    total: number;
    byStatus: Record<string, number>;
    openByPriority: Record<string, number>;
    /** Mean open -> resolved time of resolved incidents, minutes; null when none resolved. */
    mttrMinutes: number | null;
    resolvedLast7d: number;
    openedLast7d: number;
  };
  responses: { byStatus: Record<string, number>; pendingApprovalsByRole: Record<string, number> };
  verifications: { byResult: Record<string, number> };
  topTechniques: { techniqueId: string; tactic: string; incidents: number }[];
  topSources: { value: string; incidents: number }[];
  activity: { occurredAt: string; incidentId: string; incidentTitle: string; eventType: string; description: string; actor: string }[];
  /** AI analysis jobs (DB queue on agent_executions), status upper-cased: QUEUED / RUNNING / SUCCESS / PARTIAL_SUCCESS / FAILED / ... */
  aiJobs: { byStatus: Record<string, number>; total: number };
  /** Alerts without an incident: awaiting SOC triage (no disposition yet), under MONITOR, and closed by disposition. */
  triage: { pending: number; pendingLow: number; monitoring: number; byDisposition: Record<string, number> };
  /** Approval steps by role and status (pending = active step, waiting = later chain step). */
  approvals: { byRoleStatus: Record<string, Record<string, number>> };
  /** Re-hunt verification detail beyond the result counts. */
  verificationDetail: { spread: number; awaitingRehunt: number; escalationEvents: number; escalatedIncidents: number };
  /** Open incidents whose current cycle has a VALIDATED recommendation but no response ticket yet (awaiting hand-off). */
  recommendationReady: number;
  /** Incident SEVERITY of every incident that is not merged/dismissed (analyst-validated when corrected); unknown kept apart. */
  severityDistribution: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number; unknown: number };
  kpi: {
    /** Mean minutes from incident opened to its first persisted recommendation (null = no data). */
    investigationTimeMinutes: number | null;
    investigationSamples: number;
    /** Mean minutes from approval requested to the final decision of fully decided chains (null = no data). */
    timeToDecisionMinutes: number | null;
    decisionSamples: number;
    /** Open execution work (ready / in progress / awaiting re-hunt) per assignee; unassigned work per executor role. */
    workload: { assignee: string; role: string | null; open: number }[];
    /** Finished AI jobs that produced an analysis (SUCCESS + PARTIAL_SUCCESS) / all finished jobs; null = none finished. */
    automationSuccessRate: number | null;
    automationFinished: number;
  };
}

export interface OpenIncidentRow {
  id: string;
  title: string;
  status: string;
  priority: string;
  openedAt: Date;
  closedAt: Date | null;
}

export interface IDashboardReadRepository {
  /**
   * `since` (report window): event-scoped totals count only rows from that instant on; backlog snapshots (open by
   * priority, pending approvals, triage queue, awaiting re-hunt, workload) stay "as of now". Omitted = all time.
   */
  counts(tenantId: string, days: number, since?: Date | null): Promise<DashboardCounts>;
  /** Unresolved incidents (open / investigating / escalated), newest first — the SLA watchlist candidates. */
  openIncidents(tenantId: string, limit: number): Promise<OpenIncidentRow[]>;
  /** Round-trip time of a trivial query (PostgreSQL health); throws when the database is unreachable. */
  ping(): Promise<number>;
}
