import { Request, Response } from "express";
import { IWorkflowEnginePort } from "../../../application/automation/ports/IWorkflowEnginePort";

interface OrchestratorCallbackBody {
  incidentId: string;
  title: string;
  severity: string;
  summary: string;
  decision: "auto_response" | "human_approval" | "dismiss";
  riskScore: number;
}

/**
 * OrchestratorCallbackController — presentation layer.
 * Handles POST /api/v1/webhooks/orchestrator/callback.
 * The AI orchestrator (apps/ai-orchestrator) calls this after a pipeline run
 * completes and its results are persisted. This is the point where the
 * backend hands off to n8n via IWorkflowEnginePort — the orchestrator itself
 * never talks to n8n directly, keeping "what n8n workflow to call" a backend
 * (application-layer) policy decision, not something baked into the AI service.
 */
export class OrchestratorCallbackController {
  constructor(private readonly workflowEngine: IWorkflowEnginePort) {}

  handle = async (req: Request, res: Response): Promise<void> => {
    const body = req.body as OrchestratorCallbackBody;

    if (!body.incidentId || !body.decision) {
      res.status(400).json({ error: "Missing incidentId or decision" });
      return;
    }

    // "dismiss" means DecisionAgent decided no action is warranted — skip n8n entirely.
    if (body.decision === "dismiss") {
      res.status(200).json({ acknowledged: true, playbookTriggered: false });
      return;
    }

    try {
      await this.workflowEngine.triggerPlaybook({
        workflowWebhookPath: "soar/playbook-run",
        incidentId: body.incidentId,
        title: body.title,
        severity: body.severity,
        summary: body.summary,
        decision: body.decision,
        riskScore: body.riskScore,
      });
      res.status(200).json({ acknowledged: true, playbookTriggered: true });
    } catch (err) {
      // Don't fail the callback loudly — the incident and AI results are already
      // saved; a failed n8n trigger shouldn't roll any of that back. Log and
      // let an analyst notice via the dashboard instead.
      console.error("Failed to trigger n8n playbook for incident", body.incidentId, err);
      res.status(200).json({ acknowledged: true, playbookTriggered: false });
    }
  };
}
