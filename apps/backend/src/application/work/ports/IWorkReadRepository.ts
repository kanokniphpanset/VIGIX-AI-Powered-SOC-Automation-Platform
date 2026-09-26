import { ApprovalQueueRow, TicketRow } from "../WorkQueues";

export interface IncidentWorkRow {
  id: string;
  title: string;
  status: string;
  priority: string;
  openedAt: string;
  closedAt: string | null;
  investigationNumber: number;
  alertId: string;
  /** Lab attack scenario the primary alert is labelled with (VIGIX metadata), if any. */
  scenario: { id: string } | null;
  /** Policy owner from the latest INCIDENT_ASSIGNED audit (null until the first AI analysis completed). */
  responsibleRole: string | null;
  executorRole: string | null;
  /** The active (pending) approval step of any of the incident's tickets. */
  currentApproval: { role: string | null; stepOrder: number } | null;
  /** Status of the incident's most recently updated ticket. */
  responseStatus: string | null;
  aiJob: { status: string; trigger: string | null; attempt: number; at: string } | null;
  lastVerification: string | null;
  updatedAt: string;
}

export interface IncidentWorkFilters {
  status?: string[];
  priority?: string[];
  search?: string;
  limit: number;
  offset: number;
}

export interface AuditEntry {
  id: string;
  source: "audit" | "timeline";
  occurredAt: string;
  action: string;
  actor: string;
  actorEmail: string | null;
  actorRole: string | null;
  entity: string | null;
  entityId: string | null;
  description: string | null;
  metadata: unknown;
}

export interface AiJobRow {
  id: string;
  status: string;
  trigger: string | null;
  attempt: number;
  queuedAt: string | null;
  startedAt: string;
  completedAt: string | null;
  errorCode: string | null;
  errorMessage: string | null;
}

/** Read-only projections for the role workspaces (tenant-scoped SQL). */
export interface IWorkReadRepository {
  /** Newest tickets first, at most `limit` (queues are derived in memory from these rows). */
  tickets(tenantId: string, limit: number): Promise<TicketRow[]>;
  approvals(tenantId: string, limit: number): Promise<ApprovalQueueRow[]>;
  incidents(tenantId: string, filters: IncidentWorkFilters): Promise<{ items: IncidentWorkRow[]; total: number }>;
  /** null when the incident does not exist in this tenant. */
  incidentAudit(tenantId: string, incidentId: string, limit: number): Promise<AuditEntry[] | null>;
  incidentAiJobs(tenantId: string, incidentId: string): Promise<AiJobRow[] | null>;
}
