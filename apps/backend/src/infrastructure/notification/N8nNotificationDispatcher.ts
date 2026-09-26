import { INotificationDispatcherPort } from "../../application/notification/ports/INotificationDispatcherPort";
import { NotificationEvent } from "../../application/notification/events/NotificationEvent";

/**
 * N8nNotificationDispatcher — infrastructure (Ring 3), mirrors
 * N8nWorkflowEngineAdapter.ts's exact shape (same header, same error
 * behavior). This is the only class that knows n8n's notification webhook
 * URL exists. POSTs the full NotificationEvent as-is — n8n fills templates
 * from it (see docs/architecture/notification-event-contract.md), it never
 * queries Postgres.
 */
export class N8nNotificationDispatcher implements INotificationDispatcherPort {
  constructor(
    private readonly n8nBaseUrl: string,
    private readonly apiKey?: string
  ) {}

  async emit(event: NotificationEvent): Promise<void> {
    const url = `${this.n8nBaseUrl}/webhook/soar/notification`;

    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.apiKey ? { "X-N8N-API-KEY": this.apiKey } : {}),
      },
      body: JSON.stringify(event),
    });

    if (!res.ok) {
      throw new Error(`n8n notification webhook responded with ${res.status}`);
    }
  }
}
