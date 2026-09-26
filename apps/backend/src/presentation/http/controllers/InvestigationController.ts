import { Request, Response } from "express";
import {
  ListInvestigationsByIncidentUseCase,
  GetInvestigationUseCase,
  ListEvidenceUseCase,
  GetEvidenceUseCase,
  ListIocsByInvestigationUseCase,
} from "../../../application/investigation/use-cases/ReadInvestigation.usecases";
import { CreateEvidenceUseCase } from "../../../application/investigation/use-cases/CreateEvidence.usecase";
import { CreateIocUseCase } from "../../../application/investigation/use-cases/CreateIoc.usecase";
import { createEvidenceSchema, createIocSchema } from "../../../application/investigation/dto/InvestigationDtos";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";
/** Tenant from the verified JWT — never from a query parameter. */
const tenantOf = (req: Request) => req.user?.tenantId ?? DEFAULT_TENANT_ID;

const STATUS: Record<string, number> = {
  INCIDENT_NOT_FOUND: 404,
  INVESTIGATION_NOT_FOUND: 404,
  EVIDENCE_NOT_FOUND: 404,
  INVESTIGATION_NOT_ACTIVE: 409,
  DUPLICATE_IOC: 409,
  SYSTEM_EVIDENCE_TYPE: 422,
  ALERT_NOT_IN_INCIDENT: 422,
  IOC_NOT_IN_INVESTIGATION: 422,
  INVALID_IOC_VALUE: 422,
  INVALID_TIME_RANGE: 422,
  SOURCE_ALERT_NOT_FOUND: 404,
  IOC_NOT_IN_SOURCE_ALERT: 422,
};

export class InvestigationController {
  constructor(
    private readonly listByIncident: ListInvestigationsByIncidentUseCase,
    private readonly getInvestigation: GetInvestigationUseCase,
    private readonly listEvidence: ListEvidenceUseCase,
    private readonly getEvidence: GetEvidenceUseCase,
    private readonly listIocs: ListIocsByInvestigationUseCase,
    private readonly createEvidence: CreateEvidenceUseCase,
    private readonly createIoc: CreateIocUseCase
  ) {}

  private fail(res: Response, error: string | { code: string }): void {
    const body = typeof error === "string" ? { error } : { error: error.code, ...error };
    res.status(STATUS[body.error] ?? 400).json(body);
  }

  listForIncident = async (req: Request, res: Response): Promise<void> => {
    const r = await this.listByIncident.execute({ tenantId: tenantOf(req), incidentId: req.params.incidentId });
    if (r.isFailure) return this.fail(res, r.error);
    res.json({ items: r.value });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const r = await this.getInvestigation.execute({ tenantId: tenantOf(req), investigationId: req.params.investigationId });
    if (r.isFailure) return this.fail(res, r.error);
    res.json(r.value);
  };

  evidenceList = async (req: Request, res: Response): Promise<void> => {
    const r = await this.listEvidence.execute({ tenantId: tenantOf(req), investigationId: req.params.investigationId });
    if (r.isFailure) return this.fail(res, r.error);
    res.json({ items: r.value });
  };

  evidenceById = async (req: Request, res: Response): Promise<void> => {
    const r = await this.getEvidence.execute({ tenantId: tenantOf(req), evidenceId: req.params.evidenceId });
    if (r.isFailure) return this.fail(res, r.error);
    res.json(r.value);
  };

  evidenceCreate = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(createEvidenceSchema, req, res);
    if (!body) return;
    if (!req.user) return this.fail(res, "UNAUTHENTICATED");
    const r = await this.createEvidence.execute({ tenantId: tenantOf(req), investigationId: req.params.investigationId, createdBy: req.user.id, body });
    if (r.isFailure) return this.fail(res, r.error);
    res.status(201).json(r.value);
  };

  iocList = async (req: Request, res: Response): Promise<void> => {
    const r = await this.listIocs.execute({ tenantId: tenantOf(req), investigationId: req.params.investigationId });
    if (r.isFailure) return this.fail(res, r.error);
    res.json({ items: r.value });
  };

  iocCreate = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(createIocSchema, req, res);
    if (!body) return;
    if (!req.user) return this.fail(res, "UNAUTHENTICATED");
    const r = await this.createIoc.execute({ tenantId: tenantOf(req), investigationId: req.params.investigationId, createdBy: req.user.id, body });
    if (r.isFailure) return this.fail(res, r.error);
    res.status(201).json(r.value);
  };
}
