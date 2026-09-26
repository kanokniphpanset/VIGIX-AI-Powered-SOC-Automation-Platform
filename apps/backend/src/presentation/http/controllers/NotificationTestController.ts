import { Request, Response } from "express";
import { INotificationChannelAdapter } from "../../../application/notification/ports/INotificationChannelAdapter";

/**
 * NotificationTestController — manual, admin-only "ping" for each delivery
 * channel (see notification.routes.ts — gated to admin only). Calls the
 * real adapter directly, bypassing the event/routing pipeline entirely —
 * this proves a channel's own credentials work, independent of any
 * Incident/Approval/Response event.
 */
export class NotificationTestController {
  testEmail: (req: Request, res: Response) => Promise<void>;
  testDiscord: (req: Request, res: Response) => Promise<void>;
  testTelegram: (req: Request, res: Response) => Promise<void>;

  constructor(
    private readonly emailAdapter: INotificationChannelAdapter,
    private readonly discordAdapter: INotificationChannelAdapter,
    private readonly telegramAdapter: INotificationChannelAdapter
  ) {
    this.testEmail = this.testChannel(this.emailAdapter, true);
    this.testDiscord = this.testChannel(this.discordAdapter, false);
    this.testTelegram = this.testChannel(this.telegramAdapter, false);
  }

  private testChannel(adapter: INotificationChannelAdapter, requireRecipient: boolean) {
    return async (req: Request, res: Response): Promise<void> => {
      if (!adapter.isConfigured()) {
        res.status(400).json({ error: "CHANNEL_NOT_CONFIGURED", channel: adapter.channel });
        return;
      }

      const recipient = typeof req.body?.recipient === "string" ? req.body.recipient : "";
      if (requireRecipient && !recipient) {
        res.status(400).json({ error: "RECIPIENT_REQUIRED", message: "Body must include { \"recipient\": \"someone@example.com\" }" });
        return;
      }

      const outcome = await adapter.send({
        recipient,
        subject: "VIGIX Notification Test",
        body: `VIGIX Notification Test\n\nThis is a manual delivery test for the ${adapter.channel} channel.\nSent at: ${new Date().toISOString()}`,
      });

      res.status(outcome.status === "SENT" ? 200 : 502).json(outcome);
    };
  }
}
