import { Request, Response } from "express";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";

export interface CallbackOwnershipReader {
  findOwnedJob(input: { executionId: string; incidentId: string; tenantId: string }): Promise<boolean>;
}

interface OrchestratorCallbackBody {
  incidentId: string;
  executionId: string;
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
  constructor(private readonly auditLogger: AuditLogger, private readonly ownership: CallbackOwnershipReader) {}

  handle = async (req: Request, res: Response): Promise<void> => {
    const body = req.body as OrchestratorCallbackBody;

    const principal = req.principal;
    if (!principal || principal.principalType !== "SERVICE") {
      res.status(403).json({ error: "SERVICE_PRINCIPAL_REQUIRED" }); return;
    }
    if (typeof body.incidentId !== "string" || typeof body.executionId !== "string" ||
        !["auto_response", "human_approval", "dismiss"].includes(body.decision)) {
      res.status(400).json({ error: "Invalid incidentId, executionId or decision" });
      return;
    }
    if (!principal.jobIds.includes(body.executionId) ||
        !(await this.ownership.findOwnedJob({ executionId: body.executionId, incidentId: body.incidentId, tenantId: principal.tenantId }))) {
      res.status(403).json({ error: "CALLBACK_OWNERSHIP_DENIED" }); return;
    }

    await this.auditLogger
      .record({
        tenantId: principal.tenantId,
        actor: principal.id,
        action: "AI_DECISION_RECORDED",
        entity: "Incident",
        entityId: body.incidentId,
        metadata: { decision: body.decision, severity: body.severity ?? null, executionId: body.executionId, principalType: "SERVICE", advisoryOnly: true, playbookTriggered: false },
      })
      .catch((err) => console.error("Failed to record the AI decision for incident", body.incidentId, err instanceof Error ? err.message : err));

    res.status(200).json({ acknowledged: true, playbookTriggered: false });
  };
}
