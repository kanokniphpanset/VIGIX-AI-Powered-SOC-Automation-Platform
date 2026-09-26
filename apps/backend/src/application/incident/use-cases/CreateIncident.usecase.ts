import { IIncidentRepository, AlertAlreadyLinkedError, AlertAlreadyClosedError } from "../../../domain/incident/repositories/IIncidentRepository";
import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { Incident, IncidentPriority } from "../../../domain/incident/entities/Incident.entity";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";
import { IN_APP_ROLES, InAppNotifier } from "../../notification/services/InAppNotifier";

export interface DuplicateConflict {
  alertId: string;
  /** The already-linked alert that caused the conflict (the alert itself, or one with the same SIEM-side identity). */
  linkedAlertId: string;
  incidentId: string;
  reason: "ALERT_ALREADY_LINKED" | "SAME_EXTERNAL_ALERT_LINKED";
}

export type CreateIncidentFailure =
  | { code: "ALERT_NOT_FOUND"; alertIds: string[] }
  | { code: "DUPLICATE_ALERT"; conflicts: DuplicateConflict[] }
  /** The SOC already closed the alert as FALSE_POSITIVE / INFORMATIONAL: it is not re-opened as an incident. */
  | { code: "ALERT_ALREADY_TRIAGED"; alertIds: string[] };

/**
 * CreateIncidentUseCase — a human (SOC) groups 1..N EXISTING alerts into a new Incident.
 * Nothing here invents data: every alert must already be in the database, the Incident's
 * severity (`priority`) is chosen by the analyst and is independent of the alerts' severities,
 * and the whole write (incident, alert links, timeline entry, alert status) is one transaction.
 *
 * Duplicate protection, in two layers:
 *  - application: an alert that already belongs to an incident is rejected, and so is any alert
 *    whose SIEM identity (siemSource + externalAlertId) matches an alert that already belongs
 *    to one - the same SIEM event ingested twice must not open a second incident;
 *  - database: incident_alerts.alert_id is unique, which catches a concurrent race.
 */
export class CreateIncidentUseCase {
  constructor(
    private readonly incidentRepository: IIncidentRepository,
    private readonly alertRepository: IAlertRepository,
    private readonly auditLogger: AuditLogger,
    /** Queues the normal AI analysis for the new incident (e.g. SOC opened it from a LOW alert after triage). */
    private readonly aiJobs?: { enqueue(input: { tenantId: string; incidentId: string; alertId: string; trigger: "MANUAL" }): Promise<unknown> },
    private readonly inApp?: InAppNotifier
  ) {}

  async execute(input: {
    tenantId: string;
    createdBy: string;
    title: string;
    priority: IncidentPriority;
    alertIds: string[];
    note?: string | null;
    /** Timeline text for the "created" entry (automatic incidents say why they were opened). */
    timelineDescription?: string;
  }): Promise<Result<Incident, CreateIncidentFailure>> {
    const alertIds = [...new Set(input.alertIds)];

    const found = await Promise.all(alertIds.map((id) => this.alertRepository.findById(id, input.tenantId)));
    const missing = alertIds.filter((_, i) => !found[i]);
    if (missing.length > 0) return Result.fail({ code: "ALERT_NOT_FOUND", alertIds: missing });
    const alerts = found.map((a) => a!);
    const closedByTriage = alerts.filter((a) => a.workflowState === "TRIAGED" && (a.triage?.disposition === "FALSE_POSITIVE" || a.triage?.disposition === "INFORMATIONAL"));
    if (closedByTriage.length > 0) return Result.fail({ code: "ALERT_ALREADY_TRIAGED", alertIds: closedByTriage.map((a) => a.id) });

    // Every stored alert sharing a selected alert's SIEM identity (includes the alert itself).
    const twinsByAlert = await Promise.all(alerts.map((a) => this.alertRepository.findByExternalId(a.siemSource, a.externalAlertId, input.tenantId)));
    const allIds = [...new Set(twinsByAlert.flatMap((t) => t.map((x) => x.id)))];
    const linked = await this.incidentRepository.findLinkedIncidents(allIds, input.tenantId);

    const conflicts: DuplicateConflict[] = [];
    alerts.forEach((alert, i) => {
      for (const twin of twinsByAlert[i]) {
        const incidentId = linked.get(twin.id);
        if (!incidentId) continue;
        conflicts.push({
          alertId: alert.id,
          linkedAlertId: twin.id,
          incidentId,
          reason: twin.id === alert.id ? "ALERT_ALREADY_LINKED" : "SAME_EXTERNAL_ALERT_LINKED",
        });
        break;
      }
    });
    if (conflicts.length > 0) return Result.fail({ code: "DUPLICATE_ALERT", conflicts });

    let incident: Incident;
    try {
      incident = await this.incidentRepository.createWithAlerts({
        tenantId: input.tenantId,
        title: input.title,
        priority: input.priority,
        alertIds,
        createdBy: input.createdBy,
        note: input.note ?? null,
        timelineDescription: input.timelineDescription,
      });
    } catch (err) {
      if (err instanceof AlertAlreadyClosedError) return Result.fail({ code: "ALERT_ALREADY_TRIAGED", alertIds });
      if (err instanceof AlertAlreadyLinkedError) {
        return Result.fail({ code: "DUPLICATE_ALERT", conflicts: alertIds.map((alertId) => ({ alertId, linkedAlertId: alertId, incidentId: "", reason: "ALERT_ALREADY_LINKED" as const })) });
      }
      throw err;
    }

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.createdBy,
      action: "INCIDENT_CREATED",
      entity: "Incident",
      entityId: incident.id,
      metadata: { alertIds, priority: input.priority, alertSeverities: alerts.map((a) => a.severity) },
    });

    // Incident -> AI Analysis, same queue as automatic ingestion. A queueing failure never fails the incident
    // (Run AI Analysis stays available on the incident).
    await this.aiJobs
      ?.enqueue({ tenantId: input.tenantId, incidentId: incident.id, alertId: incident.alertId, trigger: "MANUAL" })
      .catch((err) => console.error("CreateIncident: failed to queue AI analysis", incident.id, err instanceof Error ? err.message : err));

    await this.inApp?.notify({
      tenantId: input.tenantId,
      eventType: "NEW_INCIDENT",
      roles: IN_APP_ROLES.NEW_INCIDENT,
      incidentId: incident.id,
      alertId: incident.alertId,
      title: `New incident (${input.priority.toUpperCase()}): ${input.title}`,
      body: `Created by ${input.createdBy} from ${alertIds.length} alert(s). AI analysis queued.`,
    });

    return Result.ok(incident);
  }
}
