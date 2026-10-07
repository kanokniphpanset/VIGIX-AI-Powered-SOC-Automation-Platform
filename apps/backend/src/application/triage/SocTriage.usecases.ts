import { IAlertRepository } from "../../domain/alert/repositories/IAlertRepository";
import { IIncidentRepository } from "../../domain/incident/repositories/IIncidentRepository";
import { Alert } from "../../domain/alert/entities/Alert.entity";
import { OPEN_WORKFLOW_STATES, TriageDecision, TriageInputError, inSocWorkflow, validateTriageInput } from "../../domain/alert/triageWorkflow";
import { CreateIncidentUseCase } from "../incident/use-cases/CreateIncident.usecase";
import type { IncidentPriority } from "../../domain/incident/entities/Incident.entity";
import { summarizeAlert } from "../../domain/alert/alertSummary";
import { IRecommendationContextRepository } from "../recommendation/ports/IRecommendationContextRepository";
import { Severity } from "../../domain/policy/entities/PolicyEvaluationTypes";
import { incidentSeverity, toSeverity } from "../../domain/incident/severity";
import { IIncidentSeverityWriter } from "./ports/IIncidentSeverityWriter";
import { AuditLogger } from "../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../shared/result/Result";
import { NotificationChoice, NotificationDecisionOutcome, NotificationDecisionService } from "./NotificationDecisionService";

export type TriageAlertError =
  | "ALERT_NOT_FOUND"
  | "ALERT_IN_INCIDENT"
  | "ALERT_ALREADY_DECIDED"
  | "NOT_IN_SOC_WORKFLOW"
  | "CLOSE_NOT_ALLOWED"
  | TriageInputError
  | "INCIDENT_NOT_CREATED";

/**
 * SOC review of ONE open alert in the Alert Inbox (no claim, no owner). No email is sent here and no AI runs here —
 * analysis and notifications belong to the incident workflow.
 *   FALSE_POSITIVE / INFORMATIONAL  MEDIUM only, reason required -> TRIAGED, closed (closed_at), audit ALERT_TRIAGED
 *   CREATE_INCIDENT                 any open MEDIUM / HIGH / CRITICAL alert -> exactly one new incident whose severity
 *                                   is the alert's Wazuh severity (CreateIncidentUseCase: AI job queued, alert
 *                                   TRIAGED/escalated), audit ALERT_ESCALATED_TO_INCIDENT
 * LOW alerts are outside the SOC workflow (NOT_IN_SOC_WORKFLOW). HIGH / CRITICAL alerts are escalated, never closed
 * from the inbox (CLOSE_NOT_ALLOWED) — they normally already have their automatic incident. Every write is conditional
 * on the alert still being open, so two analysts (or a double click) can never decide the same alert twice.
 */
export class TriageAlertUseCase {
  constructor(
    private readonly alerts: IAlertRepository,
    private readonly incidents: IIncidentRepository,
    private readonly auditLogger: AuditLogger,
    private readonly createIncident: Pick<CreateIncidentUseCase, "execute">,
    private readonly clock: () => Date = () => new Date()
  ) {}

  async execute(input: {
    tenantId: string;
    alertId: string;
    actor: string;
    decision: TriageDecision;
    reason: string | null;
    /** CREATE_INCIDENT: optional title (defaults to the Wazuh rule description). Severity is always the alert's. */
    incident?: { title?: string | null };
  }): Promise<Result<{ alert: Alert | null; incidentId: string | null }, TriageAlertError>> {
    const now = this.clock();
    const alert = await this.alerts.findById(input.alertId, input.tenantId);
    if (!alert) return Result.fail("ALERT_NOT_FOUND");
    if (!inSocWorkflow(alert.severity)) return Result.fail("NOT_IN_SOC_WORKFLOW");
    if ((await this.incidents.findLinkedIncidents([alert.id], input.tenantId)).has(alert.id)) return Result.fail("ALERT_IN_INCIDENT");
    if (!OPEN_WORKFLOW_STATES.includes(alert.workflowState)) return Result.fail("ALERT_ALREADY_DECIDED");
    if (input.decision !== "CREATE_INCIDENT" && alert.severity.toLowerCase() !== "medium") return Result.fail("CLOSE_NOT_ALLOWED");

    const reason = input.reason?.trim() || null;
    const invalid = validateTriageInput({ decision: input.decision, reason });
    if (invalid) return Result.fail(invalid);

    if (input.decision === "CREATE_INCIDENT") {
      const incidentSeverity = alert.severity.toLowerCase() as IncidentPriority;
      const title = (input.incident?.title?.trim() || summarizeAlert(alert.rawPayload).ruleDescription || `Alert ${alert.externalAlertId}`).slice(0, 200);
      const created = await this.createIncident.execute({ tenantId: input.tenantId, createdBy: input.actor, title, priority: incidentSeverity, alertIds: [alert.id], note: reason });
      if (created.isFailure) return Result.fail(created.error.code === "DUPLICATE_ALERT" ? "ALERT_IN_INCIDENT" : "INCIDENT_NOT_CREATED");
      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: input.actor,
        action: "ALERT_ESCALATED_TO_INCIDENT",
        entity: "Alert",
        entityId: alert.id,
        metadata: { alertId: alert.id, incidentId: created.value.id, severity: incidentSeverity, reason, previousState: alert.workflowState, trigger: "SOC_REVIEW" },
      });
      return Result.ok({ alert: await this.alerts.findById(alert.id, input.tenantId), incidentId: created.value.id });
    }

    const committed = await this.alerts.commitTriage(alert.id, input.tenantId, input.actor, { disposition: input.decision, reason, at: now });
    if (!committed) return Result.fail("ALERT_ALREADY_DECIDED");
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "ALERT_TRIAGED",
      entity: "Alert",
      entityId: alert.id,
      metadata: { alertId: alert.id, disposition: input.decision, reason, note: reason, severity: alert.severity, previousState: alert.workflowState, workflowState: committed.workflowState },
    });
    return Result.ok({ alert: committed, incidentId: null });
  }
}

export type IncidentCaseError = "INCIDENT_NOT_FOUND";

/** SOC "Send email / Don't send email" for an incident (the LOW-risk case decision). Never automatic. */
export class DecideIncidentNotificationUseCase {
  constructor(private readonly context: IRecommendationContextRepository, private readonly notifications: NotificationDecisionService) {}

  async execute(input: { tenantId: string; incidentId: string; actor: string; choice: NotificationChoice; note: string | null }): Promise<Result<NotificationDecisionOutcome, IncidentCaseError>> {
    const incident = await this.context.getIncidentContext(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    const severity = incidentSeverity(incident);
    const outcome = await this.notifications.decide({
      tenantId: input.tenantId,
      actor: input.actor,
      choice: input.choice,
      entity: "Incident",
      entityId: input.incidentId,
      incidentId: input.incidentId,
      subject: `[VIGIX] Incident notification: ${incident.title}`,
      body: [
        `Incident: ${incident.title}`,
        `Status: ${incident.status} · investigation cycle ${incident.investigationNumber}`,
        `Severity: ${severity} (alert severity ${incident.alertSeverity ?? "unknown"})`,
        input.note ? `SOC note: ${input.note}` : null,
        "Informational notification from the SOC. No response action was taken by this message.",
      ]
        .filter(Boolean)
        .join("\n"),
      reason: input.note,
      metadata: { severity, alertSeverity: incident.alertSeverity },
    });
    return Result.ok(outcome);
  }
}

export type ValidateSeverityError = IncidentCaseError | "INCIDENT_CLOSED" | "SEVERITY_LOCKED" | "REASON_REQUIRED";

/** Tickets in these states are mid-approval / mid-execution: their Policy decision must not be changed under them. */
const SEVERITY_LOCKING_TICKETS = ["PENDING_IR_DECISION", "PENDING_MANUAL_DECISION", "PENDING_APPROVAL", "IN_PROGRESS"];

/**
 * SOC Severity Validation. VIGIX has ONE severity source: the Wazuh rule level, mapped deterministically at ingestion
 * (alert severity = wazuhSeverity, immutable). The incident severity starts as that value; the SOC confirms it from the
 * Wazuh evidence, or overrides it — kept separate from the Wazuh value, with an optional reason. AI never produces,
 * suggests or changes either value (there is no AI severity anywhere in VIGIX).
 *   confirm  -> audit SEVERITY_VALIDATED {changed:false}
 *   override -> incident severity updated (+ timeline), audit SEVERITY_VALIDATED {wazuhSeverity, previous, severity,
 *               overridesWazuh, reason}, then Policy re-evaluates ownership (INCIDENT_ASSIGNED). Tickets created from now
 *               on use the new severity; existing tickets keep the Policy decision they were created with.
 * The reason is optional (SOC usability); when given it is kept in the timeline and the audit record.
 * Refused while a ticket is awaiting the IR decision or in progress (SEVERITY_LOCKED), and on resolved / dismissed
 * incidents.
 */
export class ValidateIncidentSeverityUseCase {
  constructor(
    private readonly context: IRecommendationContextRepository,
    private readonly writer: IIncidentSeverityWriter,
    private readonly auditLogger: AuditLogger,
    private readonly reassign?: (input: { tenantId: string; incidentId: string; actor: string }) => Promise<void>
  ) {}

  async execute(input: { tenantId: string; incidentId: string; actor: string; actorRole: string; severity: Severity; note: string | null }): Promise<
    Result<{ severity: Severity; previous: Severity; changed: boolean; wazuhSeverity: Severity | null; overridesWazuh: boolean }, ValidateSeverityError>
  > {
    const incident = await this.context.getIncidentContext(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    if (["resolved", "dismissed"].includes(incident.status)) return Result.fail("INCIDENT_CLOSED");
    const previous = incidentSeverity(incident);
    const changed = previous !== input.severity;
    const wazuhSeverity = incident.alertSeverity ? toSeverity(incident.alertSeverity) : null;
    const overridesWazuh = !!wazuhSeverity && wazuhSeverity !== input.severity;
    const reason = input.note?.trim() || null;
    if (changed && (await this.writer.ticketStatuses(input.tenantId, input.incidentId)).some((s) => SEVERITY_LOCKING_TICKETS.includes(s))) {
      return Result.fail("SEVERITY_LOCKED");
    }
    if (changed) {
      await this.writer.setSeverity({
        tenantId: input.tenantId,
        incidentId: input.incidentId,
        severity: input.severity,
        actor: input.actor,
        description: `Severity changed ${previous} -> ${input.severity} by ${input.actorRole}${wazuhSeverity ? ` (Wazuh severity ${wazuhSeverity})` : ""}${input.note ? `: ${input.note}` : ""}`,
      });
    }
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "SEVERITY_VALIDATED",
      entity: "Incident",
      entityId: input.incidentId,
      metadata: { wazuhSeverity, previous, severity: input.severity, changed, overridesWazuh, reason, note: reason, actor: input.actor, actorRole: input.actorRole, validatedAt: new Date().toISOString() },
    });
    if (changed && this.reassign) {
      try {
        await this.reassign({ tenantId: input.tenantId, incidentId: input.incidentId, actor: input.actor });
      } catch (err) {
        console.error("Policy re-assignment after severity change failed", input.incidentId, err instanceof Error ? err.message : err);
      }
    }
    return Result.ok({ severity: input.severity, previous, changed, wazuhSeverity, overridesWazuh });
  }
}
