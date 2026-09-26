import { Request, Response } from "express";
import { z } from "zod";
import { DecideIncidentNotificationUseCase, TriageAlertUseCase, ValidateIncidentSeverityUseCase } from "../../../application/triage/SocTriage.usecases";
import { TRIAGE_DECISIONS, TriageDecision } from "../../../domain/alert/triageWorkflow";
import { GetIncidentSeverityUseCase } from "../../../application/triage/IncidentSeverity.usecase";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";
const note = z.string().trim().max(2000).nullable().optional();
const notification = z.enum(["SEND", "SKIP"]);

const triageSchema = z
  .object({
    decision: z.enum(TRIAGE_DECISIONS as [string, ...string[]]),
    reason: note,
    incident: z.object({ title: z.string().trim().max(200).nullable().optional() }).strict().optional(),
  })
  .strict();
/** 422 = the analyst must supply something; 409 = the alert is not in a state to do this. */
const TRIAGE_STATUS: Record<string, number> = {
  ALERT_NOT_FOUND: 404,
  REASON_REQUIRED: 422,
  ALERT_IN_INCIDENT: 409,
  ALERT_ALREADY_DECIDED: 409,
  NOT_IN_SOC_WORKFLOW: 409,
  CLOSE_NOT_ALLOWED: 409,
  INCIDENT_NOT_CREATED: 409,
};
const notificationSchema = z.object({ notification, note }).strict();
const severityValidationSchema = z.object({ severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]), note }).strict();

/** SOC case handling: alert review (close / create incident, no email), incident email SEND/SKIP, severity validation. */
export class SocTriageController {
  constructor(
    private readonly triageAlert: Pick<TriageAlertUseCase, "execute">,
    private readonly decideNotification: DecideIncidentNotificationUseCase,
    private readonly validateSeverity: ValidateIncidentSeverityUseCase,
    private readonly incidentSeverity?: GetIncidentSeverityUseCase
  ) {}

  /** GET: Wazuh severity (rule level), SOC-validated severity and override reason — kept separate; no AI value. */
  severity = async (req: Request, res: Response): Promise<void> => {
    const result = await this.incidentSeverity!.execute({ tenantId: req.user?.tenantId ?? DEFAULT_TENANT_ID, incidentId: req.params.id });
    if (result.isFailure) return void res.status(404).json({ error: result.error });
    res.json(result.value);
  };

  triage = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(triageSchema, req, res);
    if (!body || !req.user) return void (!req.user && res.status(401).json({ error: "UNAUTHENTICATED" }));
    const result = await this.triageAlert.execute({
      tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID,
      alertId: req.params.id,
      actor: req.user.id,
      decision: body.decision as TriageDecision,
      reason: body.reason ?? null,
      incident: body.incident ? { title: body.incident.title ?? null } : undefined,
    });
    if (result.isFailure) return void res.status(TRIAGE_STATUS[result.error] ?? 409).json({ error: result.error });
    res.json({ alert: result.value.alert?.toJSON() ?? null, incidentId: result.value.incidentId });
  };

  notificationDecision = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(notificationSchema, req, res);
    if (!body || !req.user) return void (!req.user && res.status(401).json({ error: "UNAUTHENTICATED" }));
    const result = await this.decideNotification.execute({
      tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID,
      incidentId: req.params.id,
      actor: req.user.id,
      choice: body.notification,
      note: body.note ?? null,
    });
    if (result.isFailure) return void res.status(404).json({ error: result.error });
    res.json(result.value);
  };

  severityValidation = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(severityValidationSchema, req, res);
    if (!body || !req.user) return void (!req.user && res.status(401).json({ error: "UNAUTHENTICATED" }));
    const result = await this.validateSeverity.execute({
      tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID,
      incidentId: req.params.id,
      actor: req.user.id,
      actorRole: req.user.role,
      severity: body.severity,
      note: body.note ?? null,
    });
    if (result.isFailure) return void res.status(result.error === "INCIDENT_NOT_FOUND" ? 404 : result.error === "REASON_REQUIRED" ? 422 : 409).json({ error: result.error });
    res.json(result.value);
  };
}
