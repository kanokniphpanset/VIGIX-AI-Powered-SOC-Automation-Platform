import { INotificationChannelAdapter, NotificationSendInput, NotificationDeliveryOutcome } from "../../application/notification/ports/INotificationChannelAdapter";

/**
 * TelegramNotificationAdapter — infrastructure (Ring 3). The only class
 * that knows a Telegram bot token/chat id exist or what the Bot API's
 * sendMessage shape looks like. One global bot/chat (not per-role) — same
 * design as Discord, see DiscordNotificationAdapter's docstring.
 */
export class TelegramNotificationAdapter implements INotificationChannelAdapter {
  readonly channel = "telegram" as const;

  constructor(
    private readonly botToken: string | undefined,
    private readonly chatId: string | undefined,
    private readonly timeoutMs = 8000
  ) {}

  isConfigured(): boolean {
    return !!this.botToken && !!this.chatId;
  }

  async send(input: NotificationSendInput): Promise<NotificationDeliveryOutcome> {
    if (!this.botToken || !this.chatId) {
      return { status: "FAILED", channel: this.channel, errorMessage: "Telegram not configured (TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID missing)" };
    }

    const url = `https://api.telegram.org/bot${this.botToken}/sendMessage`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Telegram's 4096-char message limit.
        body: JSON.stringify({ chat_id: this.chatId, text: input.body.slice(0, 4096) }),
        signal: controller.signal,
      });
      const data = (await res.json().catch(() => null)) as { ok?: boolean; description?: string; result?: { message_id?: number } } | null;

      if (!res.ok || !data?.ok) {
        return { status: "FAILED", channel: this.channel, errorMessage: this.redact(`Telegram API error ${res.status}: ${data?.description ?? "unknown"}`) };
      }
      return {
        status: "SENT",
        channel: this.channel,
        providerMessageId: data.result?.message_id !== undefined ? String(data.result.message_id) : undefined,
        deliveredAt: new Date(),
      };
    } catch (err) {
      return { status: "FAILED", channel: this.channel, errorMessage: this.redact(this.classifyError(err)) };
    } finally {
      clearTimeout(timeout);
    }
  }

  private classifyError(err: unknown): string {
    if (err instanceof Error) {
      if (err.name === "AbortError") return "Telegram request timed out";
      return `Telegram request failed: ${err.message}`;
    }
    return "Unknown Telegram delivery error";
  }

  private redact(message: string): string {
    return this.botToken ? message.split(this.botToken).join("[redacted]") : message;
  }
}
