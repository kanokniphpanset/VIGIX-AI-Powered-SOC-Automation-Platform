import { Request, Response } from "express";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

interface OrchestratorCallbackBody {
  incidentId: string;
  title: string;
  severity: string;
  summary: string;
  decision: "auto_response" | "human_approval" | "dismiss";
  /** Severity the AI suggested (advisory). A legacy riskScore field, if still sent, is ignored. */
}

/**
 * OrchestratorCallbackController — POST /api/v1/webhooks/orchestrator/callback.
 * The AI orchestrator reports its pipeline decision here after persisting its results. VIGIX rule: AI decisions are
 * ADVISORY — this endpoint only records and acknowledges them. It never triggers an n8n playbook, an approval, a
 * response or a notification (whatever the decision, incl. "auto_response"). Any automation must be started later by
 * an explicit human action through the Policy / Approval / Response workflow.
 */
export class OrchestratorCallbackController {
  constructor(private readonly auditLogger: AuditLogger) {}

  handle = async (req: Request, res: Response): Promise<void> => {
    const body = req.body as OrchestratorCallbackBody;

    if (!body.incidentId || !body.decision) {
      res.status(400).json({ error: "Missing incidentId or decision" });
      return;
    }

    await this.auditLogger
      .record({
        tenantId: DEFAULT_TENANT_ID,
        actor: "ai-orchestrator",
        action: "AI_DECISION_RECORDED",
        entity: "Incident",
        entityId: body.incidentId,
        metadata: { decision: body.decision, severity: body.severity ?? null, advisoryOnly: true, playbookTriggered: false },
      })
      .catch((err) => console.error("Failed to record the AI decision for incident", body.incidentId, err instanceof Error ? err.message : err));

    res.status(200).json({ acknowledged: true, playbookTriggered: false });
  };
}
