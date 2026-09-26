import { randomUUID } from "crypto";
import { INotificationChannelAdapter } from "../ports/INotificationChannelAdapter";
import { INotificationDeliveryRepository } from "../../../domain/notification/repositories/INotificationDeliveryRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { IRoleEmailResolver, RoleEmailSource } from "./RoleEmailDirectory";
import { maskEmail } from "../../settings/use-cases/NotificationRecipients.usecases";
import { NotificationRole } from "../events/NotificationEvent";
import { InAppNotifier } from "./InAppNotifier";

export type IrEmailAction = "ARTICLE_SENT_TO_IR" | "RESPONSE_GUIDE_SENT_TO_IR" | "SOC_NOTIFICATION_EMAIL" | "INCIDENT_CONTEXT_EMAIL";
export type IrEmailError = "IR_TEAM_EMAIL_NOT_CONFIGURED" | "RECIPIENT_NOT_CONFIGURED" | "CHANNEL_NOT_CONFIGURED" | "DELIVERY_FAILED" | "DUPLICATE_IN_PROGRESS";

export interface IrEmailOutcome {
  status: "SENT" | "FAILED" | "NOT_SENT";
  /** IR_TEAM for the IR paths; the role-context incident email may address SOC / IR_TEAM / ADMIN. */
  recipientRole: NotificationRole;
  /** Masked (e.g. i***@corp.test) — the full address stays on the server. */
  recipient: string | null;
  sentAt: string | null;
  deliveryId: string | null;
  error: IrEmailError | null;
  /** True when this request repeated an already-sent one (same idempotency key): nothing was sent again. */
  duplicate: boolean;
}

/** Who the IR email would go to, for the confirmation dialog (masked; never the full address). */
export interface IrRecipientPreview {
  recipientRole: NotificationRole;
  recipient: string | null;
  source: RoleEmailSource;
  emailChannelConfigured: boolean;
}

/** Strips line breaks so a subject can never inject extra mail headers. */
export const safeSubject = (s: string) => s.replace(/[\r\n]+/g, " ").trim().slice(0, 200);

/**
 * IrEmailService — the one path for emailing content to the IR Team (article / response guide). Reuses the existing
 * notification architecture end to end: recipient resolved at send time by RoleEmailDirectory (Settings/DB value, else
 * IR_TEAM_EMAIL — never the caller), delivery through the same EmailNotificationAdapter the dispatcher uses, a row in
 * notification_deliveries, and an audit event (actor, entity, recipient role, delivery status) for every attempt.
 *
 * Duplicate-send protection: the caller's idempotency key becomes the delivery eventId. A key that was already SENT
 * returns that result without sending again; a key still in flight (or PENDING) is rejected.
 */
export class IrEmailService {
  private readonly inFlight = new Set<string>();

  constructor(
    private readonly emailAdapter: INotificationChannelAdapter,
    private readonly roleEmail: IRoleEmailResolver,
    private readonly deliveries: INotificationDeliveryRepository,
    private readonly auditLogger: AuditLogger,
    /** Every email actually sent is mirrored in the recipient role's in-app notifications (no email without one). */
    private readonly inApp?: InAppNotifier
  ) {}

  async previewRecipient(tenantId: string, role: NotificationRole = "IR_TEAM"): Promise<IrRecipientPreview> {
    const { email, source } = await this.roleEmail.resolve(tenantId, role);
    return { recipientRole: role, recipient: email ? maskEmail(email) : null, source, emailChannelConfigured: this.emailAdapter.isConfigured() };
  }

  async send(input: {
    tenantId: string;
    actor: string;
    action: IrEmailAction;
    entity: "KnowledgeArticle" | "Incident" | "Alert";
    entityId: string;
    incidentId: string | null;
    subject: string;
    body: string;
    idempotencyKey?: string | null;
    metadata?: Record<string, unknown>;
    /** Recipient role (resolved server-side from Settings / .env, never from the caller's address). Default IR_TEAM. */
    recipientRole?: NotificationRole;
  }): Promise<IrEmailOutcome> {
    const role: NotificationRole = input.recipientRole ?? "IR_TEAM";
    const eventId = input.idempotencyKey || randomUUID();
    const lockKey = `${input.tenantId}:${eventId}`;
    const base: IrEmailOutcome = { status: "NOT_SENT", recipientRole: role, recipient: null, sentAt: null, deliveryId: null, error: null, duplicate: false };

    // Claim the key synchronously (before any await) so two concurrent requests can never both pass the check.
    if (this.inFlight.has(lockKey)) return { ...base, error: "DUPLICATE_IN_PROGRESS", duplicate: true };
    this.inFlight.add(lockKey);
    try {
      if (input.idempotencyKey) {
        const previous = await this.deliveries.findByEventId(eventId, input.tenantId);
        const sent = previous.find((d) => d.status === "SENT");
        if (sent) {
          return { ...base, status: "SENT", recipient: maskEmail(sent.recipient), sentAt: sent.sentAt?.toISOString() ?? null, deliveryId: sent.id, duplicate: true };
        }
        if (previous.some((d) => d.status === "PENDING")) return { ...base, error: "DUPLICATE_IN_PROGRESS", duplicate: true };
        // Only FAILED attempts so far: retrying with the same key is allowed.
      }

      const subject = safeSubject(input.subject);
      const { email } = await this.roleEmail.resolve(input.tenantId, role);
      let outcome: IrEmailOutcome = { ...base, recipient: email ? maskEmail(email) : null };

      if (!email) outcome = { ...outcome, error: role === "IR_TEAM" ? "IR_TEAM_EMAIL_NOT_CONFIGURED" : "RECIPIENT_NOT_CONFIGURED" };
      else if (!this.emailAdapter.isConfigured()) outcome = { ...outcome, error: "CHANNEL_NOT_CONFIGURED" };
      else {
        const delivery = await this.deliveries.create({
          tenantId: input.tenantId,
          eventId,
          eventType: input.action,
          incidentId: input.incidentId,
          channel: "email",
          recipientRole: role,
          recipient: email,
          status: "PENDING",
        });
        let sent: Awaited<ReturnType<INotificationChannelAdapter["send"]>>;
        try {
          sent = await this.emailAdapter.send({ recipient: email, subject, body: input.body });
        } catch {
          sent = { status: "FAILED", channel: "email", errorMessage: "Email adapter error" };
        }
        const sentAt = sent.status === "SENT" ? (sent.deliveredAt ?? new Date()) : null;
        await this.deliveries
          .updateStatus(delivery.id, { status: sent.status, providerMessageId: sent.providerMessageId ?? null, errorMessage: sent.errorMessage ?? null, sentAt })
          .catch((err) => console.error("Failed to update IR email delivery status", delivery.id, err instanceof Error ? err.message : "unknown"));
        outcome = { ...outcome, status: sent.status === "SENT" ? "SENT" : "FAILED", sentAt: sentAt?.toISOString() ?? null, deliveryId: delivery.id, error: sent.status === "SENT" ? null : "DELIVERY_FAILED" };
      }

      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: input.actor,
        action: input.action,
        entity: input.entity,
        entityId: input.entityId,
        // Never the SMTP error text, the full address or any credential: only what happened.
        metadata: { ...input.metadata, recipientRole: role, deliveryStatus: outcome.status, deliveryId: outcome.deliveryId, error: outcome.error, subject, sentAt: outcome.sentAt },
      });
      if (outcome.status === "SENT" && !outcome.duplicate) {
        await this.inApp?.notify({
          tenantId: input.tenantId,
          eventType: input.action === "INCIDENT_CONTEXT_EMAIL" && role === "IR_TEAM" ? "IR_NOTIFIED" : input.action,
          roles: [role],
          incidentId: input.incidentId,
          title: `Email to ${role}: ${subject}`,
          body: `Sent by ${input.actor}.`,
        });
      }
      return outcome;
    } finally {
      this.inFlight.delete(lockKey);
    }
  }
}
