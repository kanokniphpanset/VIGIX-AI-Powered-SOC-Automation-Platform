/**
 * IWorkflowEnginePort — port (interface) owned by the application layer.
 * Whatever engine actually executes playbooks (n8n today, Temporal/Camunda
 * tomorrow) implements this. Application code never imports an n8n SDK.
 */
export interface TriggerPlaybookInput {
  workflowWebhookPath: string; // e.g. "soar/playbook-run"
  incidentId: string;
  title: string;
  severity: string;
  summary: string;
  decision: string;
}

export interface IWorkflowEnginePort {
  triggerPlaybook(input: TriggerPlaybookInput): Promise<void>;
}
