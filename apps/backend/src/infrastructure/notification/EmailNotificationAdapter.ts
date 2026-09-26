import type { Transporter } from "nodemailer";
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
    return this.transporter !== null && !!this.fromAddress;
  }

  async send(input: NotificationSendInput): Promise<NotificationDeliveryOutcome> {
    if (!this.transporter || !this.fromAddress) {
      return { status: "FAILED", channel: this.channel, errorMessage: "Email not configured (EMAIL_HOST/EMAIL_FROM missing)" };
    }

    try {
      const info = await this.transporter.sendMail({
        from: this.fromAddress,
        to: input.recipient,
        subject: input.subject ?? "VIGIX Notification",
        text: input.body,
      });
      return { status: "SENT", channel: this.channel, providerMessageId: info.messageId, deliveredAt: new Date() };
    } catch (err) {
      return { status: "FAILED", channel: this.channel, errorMessage: this.redact(this.toMessage(err)) };
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
