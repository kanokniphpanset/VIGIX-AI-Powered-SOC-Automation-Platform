import { randomUUID } from "crypto";
import { IrEmailOutcome, IrEmailService, IrRecipientPreview, safeSubject } from "../services/IrEmailService";
import { NotificationRole } from "../events/NotificationEvent";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";

/** Facts the email is built from — all stored records; nothing is inferred or invented here. */
export interface IncidentEmailContext {
  id: string;
  title: string;
  status: string;
  priority: string;
  investigationNumber: number;
  openedAt: string;
  /** Incident severity (LOW..CRITICAL) — the Policy classification. */
  severity: string;
  responsibleRole: string | null;
  aiSummary: string | null;
  mitre: string[];
  iocs: { type: string; value: string }[];
  recommendation: { number: number; status: string; summary: string } | null;
  tickets: {
    id: string;
    action: string | null;
    target: string | null;
    status: string;
    executorRole: string;
    approvals: { role: string | null; stepOrder: number; status: string; decidedAt: string | null }[];
    verification: string | null;
  }[];
}

export interface IIncidentEmailContextReader {
  read(tenantId: string, incidentId: string): Promise<IncidentEmailContext | null>;
}

/** Which context each sender role writes in (SOC investigation, IR response + IR decision, admin overview). */
export type EmailContextKind = "INVESTIGATION" | "RESPONSE" | "ADMINISTRATIVE";
export const CONTEXT_BY_SENDER: Record<string, EmailContextKind> = {
  SOC: "INVESTIGATION",
  IR_TEAM: "RESPONSE",
  admin: "ADMINISTRATIVE",
};
export const EMAIL_RECIPIENT_ROLES: readonly NotificationRole[] = ["SOC", "IR_TEAM", "ADMIN"];
/** Both workspace roles may send an incident email (content follows the sender's role). */
export const INCIDENT_EMAIL_SENDER_ROLES = ["SOC", "IR_TEAM"] as const;


export function buildContextEmail(ctx: IncidentEmailContext, kind: EmailContextKind, note: string | null, incidentUrl: string): { subject: string; body: string } {
  const ref = `INC-${ctx.id.slice(0, 8).toUpperCase()}`;
  const head = [
    `Incident: ${ref} — ${ctx.title}`,
    `Status: ${ctx.status} · Priority: ${ctx.priority} · Investigation #${ctx.investigationNumber}`,
    `Severity: ${ctx.severity} · Responsible (Policy): ${ctx.responsibleRole ?? "not assigned yet"}`,
  ];
  const lines: string[] = [];
  let subjectTopic: string;
  switch (kind) {
    case "INVESTIGATION":
      subjectTopic = "Investigation update";
      lines.push("", "INVESTIGATION CONTEXT (SOC)");
      lines.push(`AI analysis: ${ctx.aiSummary ?? "no AI analysis stored yet"}`);
      lines.push(`MITRE: ${ctx.mitre.length ? ctx.mitre.join(", ") : "none mapped"}`);
      lines.push(`IOCs (current cycle): ${ctx.iocs.length ? ctx.iocs.map((i) => `${i.type} ${i.value}`).join("; ") : "none recorded"}`);
      lines.push(ctx.recommendation ? `Recommendation #${ctx.recommendation.number} (${ctx.recommendation.status}): ${ctx.recommendation.summary}` : "Recommendation: none yet");
      break;
    case "RESPONSE":
      subjectTopic = "Response update";
      lines.push("", "RESPONSE CONTEXT (IR)");
      if (!ctx.tickets.length) lines.push("No response ticket exists for this incident yet.");
      for (const t of ctx.tickets) {
        const decision = [...t.approvals].sort((a, b) => b.stepOrder - a.stepOrder)[0];
        lines.push(`- ${t.action ?? "Response"} → ${t.target ?? "—"}: ${t.status} (executor ${t.executorRole})${decision ? ` · IR decision ${decision.status}` : ""}${t.verification ? ` · re-hunt ${t.verification}` : ""}`);
      }
      break;
    case "ADMINISTRATIVE":
      subjectTopic = "Incident notice";
      lines.push("", "ADMINISTRATIVE NOTICE");
      lines.push(`Opened: ${ctx.openedAt}`);
      lines.push(`Tickets: ${ctx.tickets.length} · Verified: ${ctx.tickets.filter((t) => t.verification).length}`);
      break;
  }
  if (note) lines.push("", `Note from sender: ${note}`);
  lines.push("", `Open in VIGIX: ${incidentUrl}`, "", "This email is informational. It does not approve, execute or close anything.");
  return { subject: safeSubject(`[VIGIX] ${subjectTopic}: ${ref} ${ctx.title}`), body: [...head, ...lines].join("\n") };
}

export type IncidentEmailError = "INCIDENT_NOT_FOUND" | "INVALID_RECIPIENT_ROLE" | "SENDER_ROLE_NOT_ALLOWED";

/**
 * IncidentContextEmailUseCase — any workspace role emails an incident summary to a role's configured address. The
 * content depends on the SENDER's role (investigation / response / approval context); the recipient address is
 * resolved from Settings / .env by role (never supplied by the client). Delivery, duplicate protection
 * (idempotency key) and per-attempt audit reuse IrEmailService; EMAIL_SENT / EMAIL_SEND_FAILED are audited as well.
 */
export class IncidentContextEmailUseCase {
  constructor(
    private readonly reader: IIncidentEmailContextReader,
    private readonly email: IrEmailService,
    private readonly auditLogger: AuditLogger,
    private readonly vigixBaseUrl: string
  ) {}

  private kind(senderRole: string): EmailContextKind | null {
    return CONTEXT_BY_SENDER[senderRole] ?? null;
  }

  async preview(input: { tenantId: string; incidentId: string; senderRole: string; recipientRole: string; note: string | null }): Promise<
    Result<{ email: { subject: string; body: string }; recipient: IrRecipientPreview; context: EmailContextKind }, IncidentEmailError>
  > {
    const kind = this.kind(input.senderRole);
    if (!kind) return Result.fail("SENDER_ROLE_NOT_ALLOWED");
    if (!EMAIL_RECIPIENT_ROLES.includes(input.recipientRole as NotificationRole)) return Result.fail("INVALID_RECIPIENT_ROLE");
    const ctx = await this.reader.read(input.tenantId, input.incidentId);
    if (!ctx) return Result.fail("INCIDENT_NOT_FOUND");
    return Result.ok({
      email: buildContextEmail(ctx, kind, input.note, `${this.vigixBaseUrl}/incidents/${ctx.id}`),
      recipient: await this.email.previewRecipient(input.tenantId, input.recipientRole as NotificationRole),
      context: kind,
    });
  }

  async send(input: {
    tenantId: string;
    incidentId: string;
    actor: string;
    senderRole: string;
    recipientRole: string;
    note: string | null;
    idempotencyKey: string | null;
  }): Promise<Result<IrEmailOutcome & { context: EmailContextKind }, IncidentEmailError>> {
    const preview = await this.preview(input);
    if (preview.isFailure) return Result.fail(preview.error);
    const { email, context } = preview.value;
    const role = input.recipientRole as NotificationRole;
    const outcome = await this.email.send({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "INCIDENT_CONTEXT_EMAIL",
      entity: "Incident",
      entityId: input.incidentId,
      incidentId: input.incidentId,
      subject: email.subject,
      body: email.body,
      idempotencyKey: input.idempotencyKey ?? randomUUID(),
      recipientRole: role,
      metadata: { incidentId: input.incidentId, context, senderRole: input.senderRole },
    });
    if (!(outcome.status === "SENT" && outcome.duplicate) && outcome.error !== "DUPLICATE_IN_PROGRESS") {
      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: input.actor,
        action: outcome.status === "SENT" ? "EMAIL_SENT" : "EMAIL_SEND_FAILED",
        entity: "Incident",
        entityId: input.incidentId,
        metadata: { incidentId: input.incidentId, context, senderRole: input.senderRole, recipientRole: role, deliveryId: outcome.deliveryId, error: outcome.error },
      });
    }
    return Result.ok({ ...outcome, context });
  }
}
