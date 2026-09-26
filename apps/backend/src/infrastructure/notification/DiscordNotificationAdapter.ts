import { INotificationChannelAdapter, NotificationSendInput, NotificationDeliveryOutcome } from "../../application/notification/ports/INotificationChannelAdapter";

/**
 * DiscordNotificationAdapter — infrastructure (Ring 3). The only class
 * that knows a Discord webhook URL exists or what its POST shape looks
 * like. One global webhook (not per-role) — the intended recipient role
 * is visible in the rendered message body, not used to pick a channel.
 */
export class DiscordNotificationAdapter implements INotificationChannelAdapter {
  readonly channel = "discord" as const;

  constructor(
    private readonly webhookUrl: string | undefined,
    private readonly timeoutMs = 8000
  ) {}

  isConfigured(): boolean {
    return !!this.webhookUrl;
  }

  async send(input: NotificationSendInput): Promise<NotificationDeliveryOutcome> {
    if (!this.webhookUrl) {
      return { status: "FAILED", channel: this.channel, errorMessage: "Discord not configured (DISCORD_WEBHOOK_URL missing)" };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(this.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Discord's 2000-char message content limit.
        body: JSON.stringify({ content: input.body.slice(0, 2000) }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        return { status: "FAILED", channel: this.channel, errorMessage: this.redact(`Discord webhook responded ${res.status}${text ? `: ${text.slice(0, 200)}` : ""}`) };
      }
      return { status: "SENT", channel: this.channel, deliveredAt: new Date() };
    } catch (err) {
      return { status: "FAILED", channel: this.channel, errorMessage: this.redact(this.classifyError(err)) };
    } finally {
      clearTimeout(timeout);
    }
  }

  private classifyError(err: unknown): string {
    if (err instanceof Error) {
      if (err.name === "AbortError") return "Discord webhook request timed out";
      return `Discord request failed: ${err.message}`;
    }
    return "Unknown Discord delivery error";
  }

  private redact(message: string): string {
    return this.webhookUrl ? message.split(this.webhookUrl).join("[redacted]") : message;
  }
}
