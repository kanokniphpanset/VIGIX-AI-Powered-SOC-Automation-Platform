export type NotificationDeliveryStatus = "PENDING" | "SENT" | "FAILED";
export type NotificationDeliveryChannel = "email" | "discord" | "telegram";

export interface NotificationDeliveryProps {
  id: string;
  tenantId: string;
  eventId: string;
  eventType: string;
  incidentId: string | null;
  channel: NotificationDeliveryChannel;
  recipientRole: string;
  /** Destination identifier only — an email address, the literal string
   * "discord", or a Telegram chat id. NEVER a secret (webhook URL, bot
   * token, SMTP password) — see NotificationDelivery model's own doc
   * comment in schema.prisma. */
  recipient: string;
  status: NotificationDeliveryStatus;
  providerMessageId: string | null;
  errorMessage: string | null;
  sentAt: Date | null;
  createdAt: Date;
}

/**
 * NotificationDelivery — an append-only record of one delivery attempt
 * (one row per role x channel per NotificationEvent). Answers: what was
 * sent, to whom, through which channel, when, did it succeed, and why not
 * if it failed. Never blocks or reverses the Incident/Approval/Response
 * workflow that caused it — this is a log, not a gate.
 */
export class NotificationDelivery {
  private constructor(private readonly props: NotificationDeliveryProps) {}

  static create(props: NotificationDeliveryProps): NotificationDelivery {
    if (!props.eventId) throw new Error("NotificationDelivery must reference an eventId");
    if (!props.channel) throw new Error("NotificationDelivery must record a channel");
    if (!props.recipientRole) throw new Error("NotificationDelivery must record a recipientRole");
    return new NotificationDelivery(props);
  }

  get id() {
    return this.props.id;
  }
  get tenantId() {
    return this.props.tenantId;
  }
  get eventId() {
    return this.props.eventId;
  }
  get eventType() {
    return this.props.eventType;
  }
  get incidentId() {
    return this.props.incidentId;
  }
  get channel() {
    return this.props.channel;
  }
  get recipientRole() {
    return this.props.recipientRole;
  }
  get recipient() {
    return this.props.recipient;
  }
  get status() {
    return this.props.status;
  }
  get providerMessageId() {
    return this.props.providerMessageId;
  }
  get errorMessage() {
    return this.props.errorMessage;
  }
  get sentAt() {
    return this.props.sentAt;
  }
  get createdAt() {
    return this.props.createdAt;
  }

  toJSON() {
    return { ...this.props };
  }
}
