import { Request, Response } from "express";
import { ListIncidentsUseCase } from "../../../application/incident/use-cases/ListIncidents.usecase";
import { GetIncidentByIdUseCase } from "../../../application/incident/use-cases/GetIncidentById.usecase";
import { GetIncidentTimelineUseCase } from "../../../application/incident/use-cases/GetIncidentTimeline.usecase";
import { UpdateIncidentStatusUseCase } from "../../../application/incident/use-cases/UpdateIncidentStatus.usecase";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

export class IncidentController {
  constructor(
    private readonly listIncidents: ListIncidentsUseCase,
    private readonly getIncidentById: GetIncidentByIdUseCase,
    private readonly getIncidentTimeline: GetIncidentTimelineUseCase,
    private readonly updateIncidentStatus: UpdateIncidentStatusUseCase
  ) {}

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
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
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const result = await this.getIncidentById.execute({ id: req.params.id, tenantId });

    if (result.isFailure) {
      res.status(404).json({ error: "Incident not found" });
      return;
    }
    res.json(result.value.toJSON());
  };

  getTimeline = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
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
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const result = await this.updateIncidentStatus.execute({
      id: req.params.id,
      tenantId,
      status: req.body.status,
    });

    if (result.isFailure) {
      const status = result.error === "NOT_FOUND" ? 404 : 400;
      res.status(status).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };
}
