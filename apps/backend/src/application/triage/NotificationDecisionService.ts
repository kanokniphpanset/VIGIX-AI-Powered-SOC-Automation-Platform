import { IrEmailOutcome, IrEmailService } from "../notification/services/IrEmailService";
import { AuditLogger } from "../../infrastructure/database/postgres/repositories/AuditLogger";

export type NotificationChoice = "SEND" | "SKIP";

export interface NotificationDecisionOutcome {
  choice: NotificationChoice;
  /** The delivery result when SEND was chosen (null for SKIP). */
  email: IrEmailOutcome | null;
}

/**
 * The SOC's explicit "Send email / Don't send email" choice for a LOW-risk case (a triaged alert or a LOW incident).
 * Nothing is ever sent automatically because a case is LOW risk — only when a human chose SEND. Email permission is
 * separate from Response approval.
 *
 * SEND reuses IrEmailService end to end (recipient from the existing per-role recipient configuration, delivery row,
 * duplicate-send protection by idempotency key: one notification per case) and is audited EMAIL_SENT (or
 * EMAIL_SEND_FAILED). SKIP sends nothing and is audited EMAIL_SKIPPED.
 */
export class NotificationDecisionService {
  constructor(private readonly irEmail: IrEmailService, private readonly auditLogger: AuditLogger) {}

  async decide(input: {
    tenantId: string;
    actor: string;
    choice: NotificationChoice;
    entity: "Alert" | "Incident";
    entityId: string;
    incidentId: string | null;
    subject: string;
    body: string;
    reason: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<NotificationDecisionOutcome> {
    if (input.choice === "SKIP") {
      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: input.actor,
        action: "EMAIL_SKIPPED",
        entity: input.entity,
        entityId: input.entityId,
        metadata: { ...input.metadata, reason: input.reason, decidedBy: input.actor },
      });
      return { choice: "SKIP", email: null };
    }

    const email = await this.irEmail.send({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "SOC_NOTIFICATION_EMAIL",
      entity: input.entity,
      entityId: input.entityId,
      incidentId: input.incidentId,
      subject: input.subject,
      body: input.body,
      // One notification per case: repeating SEND returns the first delivery instead of emailing again.
      idempotencyKey: `soc-notification:${input.entity}:${input.entityId}`,
      metadata: input.metadata,
    });
    if (!(email.status === "SENT" && email.duplicate)) {
      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: input.actor,
        action: email.status === "SENT" ? "EMAIL_SENT" : "EMAIL_SEND_FAILED",
        entity: input.entity,
        entityId: input.entityId,
        metadata: { ...input.metadata, reason: input.reason, recipientRole: email.recipientRole, deliveryId: email.deliveryId, error: email.error },
      });
    }
    return { choice: "SEND", email };
  }
}
