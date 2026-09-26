import { IInAppNotificationRepository, CreateInAppNotificationData } from "../../../domain/notification/repositories/IInAppNotificationRepository";
import { INotificationDispatcherPort } from "../ports/INotificationDispatcherPort";
import { NotificationEvent } from "../events/NotificationEvent";

/** Workflow events that exist only in-app (no email): the header bell tells each role what happened. */
export type InAppOnlyEvent = "NEW_INCIDENT" | "RESPONSE_STARTED" | "INCIDENT_ESCALATED" | "INCIDENT_RESOLVED";

const ALL_WORKFLOW = ["SOC", "IR_TEAM"];

/**
 * Who sees which event in the bell (role-aware). The two operational roles: SOC (investigation, sends to IR) and IR_TEAM
 * (decides and executes). Admin sees every row (system visibility) at query time.
 * Events not listed go to the event's own email recipients.
 */
export const IN_APP_ROLES: Record<string, string[]> = {
  NEW_INCIDENT: ["SOC"],
  RESPONSE_ASSIGNED: ["IR_TEAM", "SOC"],
  APPROVAL_APPROVED: ALL_WORKFLOW,
  APPROVAL_REJECTED: ALL_WORKFLOW,
  RESPONSE_STARTED: ALL_WORKFLOW,
  RESPONSE_COMPLETED: ALL_WORKFLOW,
  VERIFICATION_NOT_RESOLVED: ALL_WORKFLOW,
  INVESTIGATION_REOPENED: ["SOC", "IR_TEAM"],
  INCIDENT_ESCALATED: ALL_WORKFLOW,
  INCIDENT_RESOLVED: ALL_WORKFLOW,
};

const TITLE: Record<string, (e: NotificationEvent) => string> = {
  APPROVAL_REQUIRED: (e) => `IR decision required — ${e.incident.title}`,
  APPROVAL_APPROVED: (e) => `IR APPROVED — response can be executed: ${e.incident.title}`,
  APPROVAL_REJECTED: (e) => `IR REJECTED — no response will be executed: ${e.incident.title}`,
  RESPONSE_ASSIGNED: (e) => `Response Ticket awaiting IR decision — ${e.ticket?.action?.name ?? "response"} on ${e.ticket?.target ?? "target"}`,
  RESPONSE_COMPLETED: (e) => `Response completed — re-hunt required: ${e.incident.title}`,
  VERIFICATION_NOT_RESOLVED: (e) => `Re-hunt: threat still present (NOT RESOLVED) — ${e.incident.title}`,
  INVESTIGATION_REOPENED: (e) => `Investigation #${e.incident.investigationNumber} opened after re-hunt — ${e.incident.title}`,
};

const incidentLink = (incidentId: string | null) => (incidentId ? `/incidents/${incidentId}` : null);

/**
 * InAppNotifier — writes the persistent in-app notifications behind the header bell. Every workflow NotificationEvent
 * (via InAppRecordingDispatcher) and every email actually sent (via IrEmailService) is recorded, so no workflow email
 * exists without a matching in-app entry. Recording never fails the workflow action that triggered it.
 * Links are app-relative paths to existing pages (incident / response ticket / approval queue).
 */
export class InAppNotifier {
  constructor(private readonly repository: IInAppNotificationRepository, private readonly failOnError = false) {}

  async notify(input: {
    tenantId: string;
    eventType: string;
    roles: string[];
    incidentId: string | null;
    responseId?: string | null;
    /** Alert the event is about (Alert Inbox events, new incident); the bell can link straight to it. */
    alertId?: string | null;
    title: string;
    body?: string | null;
    link?: string | null;
  }): Promise<void> {
    const roles = [...new Set(input.roles)];
    const rows: CreateInAppNotificationData[] = roles.map((recipientRole) => ({
      tenantId: input.tenantId,
      eventType: input.eventType,
      recipientRole,
      incidentId: input.incidentId,
      responseId: input.responseId ?? null,
      alertId: input.alertId ?? null,
      title: input.title.slice(0, 300),
      body: input.body?.slice(0, 2000) ?? null,
      link: input.link ?? (input.responseId ? `/tickets/${input.responseId}` : input.incidentId ? incidentLink(input.incidentId) : input.alertId ? `/alerts/${input.alertId}` : null),
    }));
    try {
      await this.repository.createMany(rows);
    } catch (err) {
      if (this.failOnError) throw err;
      console.error("In-app notification could not be recorded", input.eventType, input.incidentId, err instanceof Error ? err.message : err);
    }
  }

  /** A dispatcher NotificationEvent (email/Discord/Telegram routing) -> the matching in-app notification. */
  recordEvent(event: NotificationEvent): Promise<void> {
    const roles = IN_APP_ROLES[event.eventType] ?? (event.eventType === "APPROVAL_REQUIRED" ? [...event.recipient.roles, "IR_TEAM"] : event.recipient.roles);
    const responseId = event.ticket?.id ?? null;
    return this.notify({
      tenantId: event.tenantId,
      eventType: event.eventType,
      roles,
      incidentId: event.incident?.id ?? null,
      responseId,
      title: (TITLE[event.eventType] ?? ((e: NotificationEvent) => `${e.eventType} — ${e.incident.title}`))(event),
      body: event.approval?.comment ?? event.recommendation?.summary ?? null,
      link: event.eventType === "APPROVAL_REQUIRED" ? "/tickets?queue=awaiting-decision" : responseId ? `/tickets/${responseId}` : incidentLink(event.incident?.id ?? null),
    });
  }
}

/**
 * Decorates the real dispatcher: every emitted workflow event is also recorded in-app for its roles, then delivered
 * exactly as before (email / Discord / Telegram). In-app recording can never block or fail the delivery.
 */
export class InAppRecordingDispatcher implements INotificationDispatcherPort {
  constructor(
    private readonly inner: INotificationDispatcherPort,
    private readonly notifier: InAppNotifier
  ) {}

  async emit(event: NotificationEvent): Promise<void> {
    await this.notifier.recordEvent(event).catch(() => undefined);
    await this.inner.emit(event);
  }
}
