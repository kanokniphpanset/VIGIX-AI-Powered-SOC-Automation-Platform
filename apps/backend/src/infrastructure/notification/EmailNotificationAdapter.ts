import type { Transporter } from "nodemailer";
import nodemailer from "nodemailer";
import { emailSettingsStatus, readEmailSettings } from "./EmailSettingsStore";
import { INotificationChannelAdapter, NotificationSendInput, NotificationDeliveryOutcome } from "../../application/notification/ports/INotificationChannelAdapter";

/**
 * EmailNotificationAdapter — infrastructure (Ring 3). The only class that
 * knows nodemailer/SMTP exists. `transporter` is null when EMAIL_HOST isn't
 * configured (see container.ts) — isConfigured() lets the dispatcher skip
 * this channel cleanly instead of attempting and failing every time.
 */
export class EmailNotificationAdapter implements INotificationChannelAdapter {
  readonly channel = "email" as const;

  constructor(
    private readonly transporter: Transporter | null,
    private readonly fromAddress: string | undefined,
    /** Kept only to redact it out of any SMTP error message — never logged itself. */
    private readonly password: string | undefined
  ) {}

  isConfigured(): boolean {
    try { if (emailSettingsStatus().source === "settings") return emailSettingsStatus().configured; } catch { return false; }
    return this.transporter !== null && !!this.fromAddress;
  }

  async send(input: NotificationSendInput): Promise<NotificationDeliveryOutcome> {
    let saved;
    try { saved = readEmailSettings(); }
    catch { return { status: "FAILED", channel: this.channel, errorMessage: "Email credential unavailable" }; }
    const transporter = saved ? nodemailer.createTransport({ host: "smtp.gmail.com", port: 587, secure: false, requireTLS: true, auth: { user: saved.user, pass: saved.password }, connectionTimeout: 10000, socketTimeout: 20000 }) : this.transporter;
    const fromAddress = saved?.user ?? this.fromAddress;
    if (!transporter || !fromAddress) {
      return { status: "FAILED", channel: this.channel, errorMessage: "Email not configured (EMAIL_HOST/EMAIL_FROM missing)" };
    }

    try {
      const info = await transporter.sendMail({
        from: fromAddress,
        to: input.recipient,
        subject: input.subject ?? "VIGIX Notification",
        text: input.body,
      });
      return { status: "SENT", channel: this.channel, providerMessageId: info.messageId, deliveredAt: new Date() };
    } catch (err) {
      return { status: "FAILED", channel: this.channel, errorMessage: saved ? "Gmail delivery failed; check sender credentials and provider settings" : this.redact(this.toMessage(err)) };
    }
  }

  private toMessage(err: unknown): string {
    if (err instanceof Error) return err.message;
    return "Unknown SMTP error";
  }

  private redact(message: string): string {
    if (this.password && message.includes(this.password)) {
      return message.split(this.password).join("[redacted]");
    }
    return message;
  }
}
