import { Alert } from "../../../domain/alert/entities/Alert.entity";
import { InboxSort, InboxStatus, SlaMinutesBySeverity } from "../../../domain/alert/triageWorkflow";

/**
 * Server-side Alert Inbox query: every filter, the ordering and the page run in the database (no in-memory window).
 * Only MEDIUM / HIGH / CRITICAL alerts are ever returned (LOW alerts are outside the SOC workflow).
 */
export interface InboxQueryParams {
  tenantId: string;
  /** needs-review (open, no incident) | in-incident | closed (FP / informational) | all. */
  status: InboxStatus;
  severity?: string;
  source?: string;
  /** Wazuh agent (host) name, exact, case-insensitive. */
  agent?: string;
  /** MITRE technique id; a parent id also matches its sub-techniques. */
  mitre?: string;
  incident?: "linked" | "unlinked";
  /** Alerts tagged with one of these test-scenario ids. */
  scenarioIds?: string[];
  /** Mock alerts only: external id starts with one of `prefixes` or equals one of `exact` (empty → nothing). */
  mockExternalIds?: { prefixes: string[]; exact: string[] };
  /** Free text over the alert id and the stored Wazuh payload; also matches alerts tagged with searchScenarioIds. */
  search?: string;
  searchScenarioIds?: string[];
  from?: Date;
  to?: Date;
  sort: InboxSort;
  /** Triage SLA targets from Policy (TRIAGE_SLA) — used for the SLA due time and the urgency ordering. */
  slaMinutes: SlaMinutesBySeverity;
  limit: number;
  offset: number;
}

export interface InboxQueryRow {
  alert: Alert;
  incident: { id: string; title: string; status: string; priority: string } | null;
  scenarioId: string | null;
  slaDueAt: Date | null;
}

export interface IAlertInboxQuery {
  query(params: InboxQueryParams): Promise<{ rows: InboxQueryRow[]; total: number }>;
}
