import { IWorkflowEnginePort, TriggerPlaybookInput } from "../../application/automation/ports/IWorkflowEnginePort";

/**
 * N8nWorkflowEngineAdapter — infrastructure (Ring 3).
 * Implements IWorkflowEnginePort by POSTing to an n8n webhook trigger
 * (see automation/n8n/workflows/playbook-runner.json). This is the ONLY
 * class in the backend that knows n8n exists, or what its webhook URL
 * shape looks like.
 *
 * NOT YET WIRED into container.ts / the ingest pipeline — the next step to
 * close this loop is calling triggerPlaybook() from DecisionAgent's result
 * handler once the orchestrator posts a decision back to the backend.
 */
export class N8nWorkflowEngineAdapter implements IWorkflowEnginePort {
  constructor(private readonly n8nBaseUrl: string, private readonly apiKey?: string) {}

  async triggerPlaybook(input: TriggerPlaybookInput): Promise<void> {
    const url = `${this.n8nBaseUrl}/webhook/${input.workflowWebhookPath}`;

    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.apiKey ? { "X-N8N-API-KEY": this.apiKey } : {}),
      },
      body: JSON.stringify({
        incidentId: input.incidentId,
        title: input.title,
        severity: input.severity,
        summary: input.summary,
        decision: input.decision,
        riskScore: input.riskScore,
      }),
    });

    if (!res.ok) {
      throw new Error(`n8n webhook responded with ${res.status}`);
    }
  }
}
