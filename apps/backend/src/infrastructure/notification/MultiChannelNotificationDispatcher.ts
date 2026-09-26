import { INotificationDispatcherPort } from "../../application/notification/ports/INotificationDispatcherPort";
import { INotificationChannelAdapter } from "../../application/notification/ports/INotificationChannelAdapter";
import { NotificationEvent, NotificationRole, NotificationChannel } from "../../application/notification/events/NotificationEvent";
import { INotificationDeliveryRepository } from "../../domain/notification/repositories/INotificationDeliveryRepository";
import { renderEmail, renderForChannel } from "../../application/notification/services/NotificationTemplateRenderer";
import { IRoleEmailResolver } from "../../application/notification/services/RoleEmailDirectory";

/**
 * MultiChannelNotificationDispatcher — infrastructure (Ring 3), implements
 * the EXISTING INotificationDispatcherPort (unchanged — every one of the 5
 * use-cases wired in Phase N2 already just calls `dispatcher.emit(event)`
 * and needs no changes). Replaces N8nNotificationDispatcher as the bound
 * implementation: this is where "Routing" (already built — recipient.roles
 * + recipient.channels on the event) meets "Delivery" (real Email/Discord/
 * Telegram sends), entirely in-process, no n8n involved.
 *
 * Never lets a channel failure — or even a failure to persist the delivery
 * log — propagate out of emit(): every per-(role, channel) attempt is
 * isolated in its own try/catch, so one FAILED channel never affects the
 * others, and emit() itself never rejects (the use-case's own try/catch
 * around dispatcher.emit() remains a pure safety net, not the only guard).
 */
export class MultiChannelNotificationDispatcher implements INotificationDispatcherPort {
  constructor(
    private readonly emailAdapter: INotificationChannelAdapter,
    private readonly discordAdapter: INotificationChannelAdapter,
    private readonly telegramAdapter: INotificationChannelAdapter,
    private readonly deliveryRepository: INotificationDeliveryRepository,
    /** Role -> email address, resolved at send time: the admin's Settings
     * value for the tenant, else the IR_TEAM_EMAIL/SOC_EMAIL
     * server default (the convention established for the n8n path, N3/N3.5). */
    private readonly roleEmail: IRoleEmailResolver
  ) {}

  private adapterFor(channel: NotificationChannel): INotificationChannelAdapter {
    if (channel === "email") return this.emailAdapter;
    if (channel === "discord") return this.discordAdapter;
    return this.telegramAdapter;
  }

  /** Discord/Telegram are one global destination (not per-role) — see
   * DiscordNotificationAdapter's docstring; the role is visible in the
   * rendered message body instead. Email is the one channel where routing
   * genuinely picks a different destination per role. */
  private async resolveRecipient(channel: NotificationChannel, role: NotificationRole, tenantId: string): Promise<string | null> {
    if (channel === "email") return (await this.roleEmail.resolve(tenantId, role)).email;
    return channel; // "discord" / "telegram" — a destination identifier, never a secret
  }

  async emit(event: NotificationEvent): Promise<void> {
    const incidentId = event.incident?.id ?? null;

    let alreadySent = new Set<string>();
    try {
      const existing = await this.deliveryRepository.findByEventId(event.eventId, event.tenantId);
      alreadySent = new Set(existing.filter((d) => d.status === "SENT").map((d) => `${d.recipientRole}:${d.channel}`));
    } catch (err) {
      console.error("Failed to check existing NotificationDelivery rows for idempotency", event.eventId, err);
    }

    for (const role of event.recipient.roles) {
      for (const channel of event.recipient.channels) {
        const key = `${role}:${channel}`;
        if (alreadySent.has(key)) continue; // idempotent: this event already delivered on this role+channel

        const adapter = this.adapterFor(channel);
        const recipient = await this.resolveRecipient(channel, role, event.tenantId);
        if (!recipient || !adapter.isConfigured()) continue; // never attempt a channel with no credential configured

        await this.deliverOne(event, incidentId, role, channel, recipient, adapter);
      }
    }
  }

  private async deliverOne(
    event: NotificationEvent,
    incidentId: string | null,
    role: NotificationRole,
    channel: NotificationChannel,
    recipient: string,
    adapter: INotificationChannelAdapter
  ): Promise<void> {
    let deliveryId: string;
    try {
      const created = await this.deliveryRepository.create({
        tenantId: event.tenantId,
        eventId: event.eventId,
        eventType: event.eventType,
        incidentId,
        channel,
        recipientRole: role,
        recipient,
        status: "PENDING",
      });
      deliveryId = created.id;
    } catch (err) {
      console.error("Failed to create NotificationDelivery row — skipping send to avoid an unlogged delivery", event.eventId, role, channel, err);
      return;
    }

    const message = channel === "email" ? renderEmail(event) : { subject: undefined, body: renderForChannel(event, channel) };

    try {
      const outcome = await adapter.send({ recipient, subject: message.subject, body: message.body });
      await this.deliveryRepository.updateStatus(deliveryId, {
        status: outcome.status,
        providerMessageId: outcome.providerMessageId ?? null,
        errorMessage: outcome.errorMessage ?? null,
        sentAt: outcome.status === "SENT" ? (outcome.deliveredAt ?? new Date()) : null,
      });
    } catch (err) {
      console.error("Notification adapter threw unexpectedly (should normally return FAILED instead)", event.eventId, role, channel, err);
      await this.deliveryRepository
        .updateStatus(deliveryId, { status: "FAILED", errorMessage: err instanceof Error ? err.message : "Unknown delivery error" })
        .catch(() => undefined);
    }
  }
}
