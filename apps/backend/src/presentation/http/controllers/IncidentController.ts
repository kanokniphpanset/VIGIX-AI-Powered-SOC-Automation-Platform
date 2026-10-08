import { Request, Response } from "express";
import { ListIncidentsUseCase } from "../../../application/incident/use-cases/ListIncidents.usecase";
import { GetIncidentByIdUseCase } from "../../../application/incident/use-cases/GetIncidentById.usecase";
import { GetIncidentTimelineUseCase } from "../../../application/incident/use-cases/GetIncidentTimeline.usecase";
import { UpdateIncidentStatusUseCase } from "../../../application/incident/use-cases/UpdateIncidentStatus.usecase";
import { ListIocsByIncidentUseCase } from "../../../application/incident/use-cases/ListIocsByIncident.usecase";
import { ListMitreMappingsByIncidentUseCase } from "../../../application/incident/use-cases/ListMitreMappingsByIncident.usecase";
import { CreateIncidentUseCase } from "../../../application/incident/use-cases/CreateIncident.usecase";
import { ListAlertsByIncidentUseCase } from "../../../application/incident/use-cases/ListAlertsByIncident.usecase";
import { createIncidentSchema } from "../../../application/incident/dto/CreateIncidentDto";
import { MergeAlertsIntoIncidentUseCase } from "../../../application/incident/use-cases/MergeAlertsIntoIncident.usecase";
import { GetIncidentAiAnalysisUseCase } from "../../../application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { IncidentSlaService } from "../../../application/sla/IncidentSlaService";
import { GetIncidentAlertFactsUseCase } from "../../../application/incident/use-cases/GetIncidentAlertFacts.usecase";
import { IncidentResponseSetupService, ResponseSetupError } from "../../../application/incident/services/IncidentResponseSetupService";
import { Result } from "../../../shared/result/Result";
import { z } from "zod";

const mergeAlertsSchema = z.object({ alertIds: z.array(z.string().min(1)).min(1).max(100) }).strict();
const incidentTypeSchema = z.object({ incidentType: z.string().trim().min(1).max(64).nullable() }).strict();
const caseGuidanceSchema = z.object({ allowedActions: z.array(z.string().trim().min(1)).min(1).max(50), instructions: z.string().trim().max(2000).nullable().optional() }).strict();
const groupGuidanceSchema = z.object({ allowedActions: z.array(z.string().trim().min(1)).min(1).max(50), note: z.string().trim().max(2000).nullable().optional() }).strict();
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

export class IncidentController {
  constructor(
    private readonly listIncidents: ListIncidentsUseCase,
    private readonly getIncidentById: GetIncidentByIdUseCase,
    private readonly getIncidentTimeline: GetIncidentTimelineUseCase,
    private readonly updateIncidentStatus: UpdateIncidentStatusUseCase,
    private readonly listIocsByIncident: ListIocsByIncidentUseCase,
    private readonly listMitreMappingsByIncident: ListMitreMappingsByIncidentUseCase,
    private readonly createIncident: CreateIncidentUseCase,
    private readonly listAlertsByIncident: ListAlertsByIncidentUseCase,
    private readonly mergeAlerts?: MergeAlertsIntoIncidentUseCase,
    private readonly aiAnalysis?: GetIncidentAiAnalysisUseCase,
    private readonly slaService?: IncidentSlaService,
    private readonly alertFacts?: GetIncidentAlertFactsUseCase,
    private readonly responseSetup?: IncidentResponseSetupService
  ) {}

  /** GET /incidents/:id/response-setup — incident type, group / case guidance and what a Recommendation must follow. */
  /** Read-only: the incident's group (type + severity), its response policy and the incidents in the group. */
  getResponseGroup = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.responseSetup!.groupOverview(req.params.id, tenantId);
    if (result.isFailure) { res.status(404).json({ error: result.error }); return; }
    res.json(result.value);
  };

  getResponseSetup = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.responseSetup!.get(req.params.id, tenantId);
    if (result.isFailure) return void res.status(404).json({ error: result.error });
    res.json(result.value);
  };

  /** PUT /incidents/:id/incident-type { incidentType | null } — SOC confirms / changes the type (null = MITRE detection). */
  setIncidentType = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(incidentTypeSchema, req, res);
    if (!body) return;
    const result = await this.responseSetup!.setIncidentType({ tenantId: req.user!.tenantId, incidentId: req.params.id, actor: req.user!.id, incidentType: body.incidentType });
    this.sendSetup(res, result);
  };

  /** PUT /incidents/:id/response-guidance { allowedActions, instructions } — this case only. DELETE clears it. */
  setCaseGuidance = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(caseGuidanceSchema, req, res);
    if (!body) return;
    const result = await this.responseSetup!.setCaseGuidance({ tenantId: req.user!.tenantId, incidentId: req.params.id, actor: req.user!.id, guidance: { allowedActions: body.allowedActions, instructions: body.instructions ?? null } });
    this.sendSetup(res, result);
  };

  clearCaseGuidance = async (req: Request, res: Response): Promise<void> => {
    const result = await this.responseSetup!.setCaseGuidance({ tenantId: req.user!.tenantId, incidentId: req.params.id, actor: req.user!.id, guidance: null });
    this.sendSetup(res, result);
  };

  /** PUT /incidents/:id/response-guidance/group { allowedActions, note } — RESPONSE_GUIDANCE policy of the incident's group. */
  saveGroupGuidance = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(groupGuidanceSchema, req, res);
    if (!body) return;
    const result = await this.responseSetup!.saveGroupGuidance({ tenantId: req.user!.tenantId, incidentId: req.params.id, actor: req.user!.id, allowedActions: body.allowedActions, note: body.note ?? null });
    this.sendSetup(res, result);
  };

  private sendSetup(res: Response, result: Result<unknown, ResponseSetupError>): void {
    if (result.isSuccess) return void res.json(result.value);
    const status = result.error === "INCIDENT_NOT_FOUND" ? 404 : result.error === "INCIDENT_CLOSED" ? 409 : 422;
    res.status(status).json({ error: result.error });
  }

  /** GET /incidents/:id/alert-facts — Investigation table: each alert's key facts for the incident type; read-only. */
  getAlertFacts = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.alertFacts!.execute({ incidentId: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value);
  };

  /** GET /incidents/:id/sla — Policy-derived SLA clocks (first response, resolution); read-only. */
  getSla = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const incident = await this.getIncidentById.execute({ id: req.params.id, tenantId });
    if (incident.isFailure) {
      res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
      return;
    }
    const i = incident.value;
    res.json(await this.slaService!.forIncident(tenantId, { id: i.id, status: i.status, openedAt: i.openedAt, closedAt: i.closedAt }));
  };

  /** GET /incidents/:id/ai-analysis — latest risk score + LLM analyst interpretation (not evidence). */
  getAiAnalysis = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.aiAnalysis!.execute({ tenantId, incidentId: req.params.id });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value);
  };

  /** POST /incidents/:id/alerts — Set Group: move the selected related alerts (and their auto-created incidents) into this one. */
  addAlerts = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const body = validateBody(mergeAlertsSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.mergeAlerts!.execute({ tenantId, incidentId: req.params.id, alertIds: body.alertIds, actor: req.user.id });
    if (result.isFailure) {
      const f = result.error;
      res.status(f.code === "ALERT_NOT_FOUND" || f.code === "INCIDENT_NOT_FOUND" || f.code === "SOURCE_NOT_FOUND" ? 404 : 409).json({ error: f.code, ...f });
      return;
    }
    res.json(result.value);
  };

  create = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const body = validateBody(createIncidentSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }

    const result = await this.createIncident.execute({
      tenantId,
      createdBy: req.user.id,
      title: body.title,
      priority: body.priority,
      alertIds: body.alertIds,
      note: body.note ?? null,
    });
    if (result.isFailure) {
      const failure = result.error;
      res.status(failure.code === "ALERT_NOT_FOUND" ? 404 : 409).json({ error: failure.code, ...failure });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  getAlerts = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.listAlertsByIncident.execute({ incidentId: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json({ items: result.value.map((a) => a.toJSON()) });
  };

  getIocs = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.listIocsByIncident.execute({ incidentId: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json({ items: result.value });
  };

  getMitreMappings = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.listMitreMappingsByIncident.execute({ incidentId: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json({ items: result.value });
  };

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const limit = req.query.limit ? Number(req.query.limit) : 25;
    const offset = req.query.offset ? Number(req.query.offset) : 0;

    const result = await this.listIncidents.execute({ tenantId, limit, offset });

    res.json({
      items: result.value.items.map((i) => i.toJSON()),
      total: result.value.total,
      limit: result.value.limit,
      offset: result.value.offset,
    });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.getIncidentById.execute({ id: req.params.id, tenantId });

    if (result.isFailure) {
      res.status(404).json({ error: "Incident not found" });
      return;
    }
    res.json(result.value.toJSON());
  };

  getTimeline = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.getIncidentTimeline.execute({
      incidentId: req.params.id,
      tenantId,
    });

    if (result.isFailure) {
      res.status(404).json({ error: "Incident not found" });
      return;
    }
    res.json(result.value);
  };

  updateStatus = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.updateIncidentStatus.execute({
      id: req.params.id,
      tenantId,
      status: req.body.status,
      actor: req.user?.id,
    });

    if (result.isFailure) {
      const status = result.error === "NOT_FOUND" ? 404 : result.error === "RESOLVE_REQUIRES_VERIFICATION" ? 409 : 400;
      res.status(status).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };
}
