import { NotificationEvent } from "../events/NotificationEvent";

/**
 * INotificationDispatcherPort — port (interface) owned by the application
 * layer, mirroring IWorkflowEnginePort's existing shape. Whatever actually
 * delivers notifications (n8n today) implements this; application code
 * never imports an n8n SDK or knows a webhook URL exists.
 */
export interface INotificationDispatcherPort {
  emit(event: NotificationEvent): Promise<void>;
}
