import { Incident, IncidentPriority } from "../entities/Incident.entity";
import { Alert } from "../../alert/entities/Alert.entity";

export interface IncidentTimelineEntry {
  id: string;
  incidentId: string;
  eventType: string;
  description: string;
  actor: string;
  occurredAt: Date;
}

export interface CreateIncidentWithAlertsData {
  tenantId: string;
  title: string;
  /** The Incident's own severity - chosen by the analyst, independent of the alerts' severities. */
  priority: IncidentPriority;
  /** 1..N existing alert ids; the first is stored as the originating Incident.alertId. */
  alertIds: string[];
  createdBy: string;
  note: string | null;
  /** Timeline text for the "created" entry (default: the manual-creation wording). */
  timelineDescription?: string;
}

/** Thrown by createWithAlerts when an alert was linked to another incident between the duplicate check and the insert. */
export class AlertAlreadyLinkedError extends Error {
  constructor() {
    super("ALERT_ALREADY_LINKED");
  }
}

/** Thrown by createWithAlerts when an alert was closed (FALSE_POSITIVE / INFORMATIONAL) before the incident committed. */
export class AlertAlreadyClosedError extends Error {
  constructor() {
    super("ALERT_ALREADY_TRIAGED");
  }
}

/** Why an analyst's Set Group merge cannot absorb a source incident (checked inside the merge transaction). */
export type MergeBlockReason = "SOURCE_HAS_RESPONSE" | "SOURCE_RESOLVED" | "SOURCE_IS_TARGET" | "TARGET_NOT_OPEN" | "SOURCE_NOT_FOUND";

export class MergeBlockedError extends Error {
  constructor(
    readonly reason: MergeBlockReason,
    readonly incidentId: string
  ) {
    super(reason);
  }
}

export interface AbsorbIntoIncidentData {
  tenantId: string;
  targetIncidentId: string;
  /** Other incidents whose alerts all move to the target; each is then closed as merged (status "dismissed"). */
  sourceIncidentIds: string[];
  /** Alerts that belong to no incident yet; linked to the target directly. */
  unlinkedAlertIds: string[];
  actor: string;
}

export interface IIncidentRepository {
  /** Incidents by id (tenant-scoped); missing ids are simply absent from the result. */
  findByIds(ids: string[], tenantId: string): Promise<Incident[]>;
  /**
   * Set Group (analyst correlation), atomically: every alert of each source incident is re-linked to the target,
   * unlinked alerts are linked to it, each source incident is closed as merged, and both sides get timeline
   * entries. Throws MergeBlockedError (nothing written) when the target is not open, or a source is resolved or
   * already has response plans (its work must not be orphaned). Returns the alert ids now added to the target.
   */
  absorbIntoIncident(data: AbsorbIntoIncidentData): Promise<string[]>;
  /** Atomically: Incident + incident_alerts rows + "created" timeline entry + alerts marked escalated. */
  createWithAlerts(data: CreateIncidentWithAlertsData): Promise<Incident>;
  /** alertId -> incidentId for every given alert that already belongs to an incident (incident_alerts OR Incident.alertId). */
  findLinkedIncidents(alertIds: string[], tenantId: string): Promise<Map<string, string>>;
  /** All alerts of an incident: incident_alerts plus the originating Incident.alertId. */
  findAlerts(incidentId: string, tenantId: string): Promise<Alert[]>;
  findById(id: string, tenantId: string): Promise<Incident | null>;
  findAll(tenantId: string, limit?: number, offset?: number): Promise<Incident[]>;
  countAll(tenantId: string): Promise<number>;
  findTimeline(incidentId: string): Promise<IncidentTimelineEntry[]>;
  updateStatus(id: string, tenantId: string, status: Incident["status"]): Promise<Incident>;
  /** Appends one incident timeline entry. */
  addTimelineEntry(incidentId: string, entry: { eventType: string; description: string; actor: string }): Promise<void>;
  /** Bumps investigationNumber by 1 — the ONLY way a new Investigation cycle begins
   * (Verification's NOT_RESOLVED/spreadDetected/threatContained=false path). Never
   * decremented, never set directly. */
  incrementInvestigationNumber(id: string, tenantId: string): Promise<Incident>;
}
