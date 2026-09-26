import { NotificationDeliveryChannel } from "../../../domain/notification/entities/NotificationDelivery.entity";

/**
 * INotificationChannelAdapter — one implementation per delivery channel
 * (Email/Discord/Telegram). Mirrors IWorkflowEnginePort/IRecommendationAgentPort's
 * existing pattern: application code depends only on this interface, never
 * on nodemailer, a Discord webhook shape, or the Telegram Bot API directly.
 *
 * An adapter NEVER throws a provider-specific error — every outcome
 * (success, HTTP error, timeout, network failure) is normalized into a
 * NotificationDeliveryResult so the caller (MultiChannelNotificationDispatcher)
 * never needs to know which provider it just called.
 */
export interface NotificationSendInput {
  /** Destination — an email address, or ignored by Discord/Telegram
   * adapters (which send to one configured webhook/chat regardless of who
   * the intended human recipient is; the role is in the message body). */
  recipient: string;
  subject?: string;
  body: string;
}

export type NotificationDeliveryOutcomeStatus = "SENT" | "FAILED";

export interface NotificationDeliveryOutcome {
  status: NotificationDeliveryOutcomeStatus;
  channel: NotificationDeliveryChannel;
  providerMessageId?: string;
  /** Never a raw provider exception and never a secret — see each
   * adapter's own redaction. */
  errorMessage?: string;
  deliveredAt?: Date;
}

export interface INotificationChannelAdapter {
  readonly channel: NotificationDeliveryChannel;
  /** True when this channel has enough configuration to attempt a real
   * send (e.g. DISCORD_WEBHOOK_URL is set) — lets the dispatcher skip a
   * channel cleanly instead of attempting and failing every time. */
  isConfigured(): boolean;
  send(input: NotificationSendInput): Promise<NotificationDeliveryOutcome>;
}
