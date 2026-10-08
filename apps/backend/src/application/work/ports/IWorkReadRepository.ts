import { ApprovalQueueRow, TicketRow } from "../WorkQueues";
import { CaseFingerprint } from "../../../domain/incident/similarCases";

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

/** One indicator across every incident of the tenant (threat_intel_iocs grouped by type + value). */
export interface IocLibraryRow {
  iocType: string;
  iocValue: string;
  sources: string[];
  /** Highest stored reputation (0–100) / confidence across sightings; null when no provider scored it. */
  reputationScore: number | null;
  confidence: number | null;
  firstSeen: string | null;
  lastSeen: string | null;
  caseCount: number;
  /** Incidents the indicator was recorded on, newest first. */
  cases: { id: string; title: string; status: string; openedAt: string | null }[];
}

/** A closed incident as a similar-case candidate: its fingerprint plus how it was handled. */
export interface ClosedCaseRow extends CaseFingerprint {
  id: string;
  title: string;
  status: string;
  priority: string;
  openedAt: string;
  closedAt: string | null;
  /** Investigation rounds it took (1 = closed in the first round). */
  investigationNumber: number;
  /** Result of its most recent verification (re-hunt), null when never verified. */
  lastVerification: string | null;
  /** Its Response Tickets: the catalog action (code/name), target and final status. */
  actions: { code: string | null; name: string | null; target: string | null; status: string }[];
  /** The note recorded when it was closed (INCIDENT_CLOSED audit), e.g. why the SOC rejected the recommendation. */
  closeNote: string | null;
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
  /** Most-sighted indicators first, at most `limit`; `total` is the number of distinct indicators. */
  iocLibrary(tenantId: string, limit: number): Promise<{ items: IocLibraryRow[]; total: number }>;
  /**
   * The incident's fingerprint and the most recently closed (resolved / dismissed) incidents of the same tenant, at
   * most `candidateLimit`, each with its fingerprint and outcome. null when the incident does not exist in this tenant.
   */
  similarCaseFacts(tenantId: string, incidentId: string, candidateLimit: number): Promise<{ target: CaseFingerprint & { id: string }; candidates: ClosedCaseRow[] } | null>;
}
