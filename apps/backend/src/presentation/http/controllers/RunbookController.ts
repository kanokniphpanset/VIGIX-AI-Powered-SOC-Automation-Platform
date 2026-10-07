import { authenticatedTenant } from "../middlewares/auth.middleware";
import { Request, Response } from "express";
import { CreateRunbookUseCase } from "../../../application/runbook/use-cases/CreateRunbook.usecase";
import { UpdateRunbookUseCase } from "../../../application/runbook/use-cases/UpdateRunbook.usecase";
import { GetRunbookUseCase } from "../../../application/runbook/use-cases/GetRunbook.usecase";
import { ListRunbooksUseCase } from "../../../application/runbook/use-cases/ListRunbooks.usecase";
import { createRunbookSchema, updateRunbookSchema } from "../../../application/runbook/dto/RunbookDto";
import { validateBody } from "../validators/validateBody";


export class RunbookController {
  constructor(
    private readonly createRunbook: CreateRunbookUseCase,
    private readonly updateRunbook: UpdateRunbookUseCase,
    private readonly getRunbook: GetRunbookUseCase,
    private readonly listRunbooks: ListRunbooksUseCase
  ) {}

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const runbooks = await this.listRunbooks.execute({ tenantId });
    res.json({ items: runbooks.map((r) => r.toJSON()) });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const result = await this.getRunbook.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "INVALID_RUNBOOK" });
      return;
    }
    res.json(result.value.toJSON());
  };

  create = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const body = validateBody(createRunbookSchema, req, res);
    if (!body) return;
    const result = await this.createRunbook.execute({
      ...body,
      tenantId,
      version: body.version ?? "1.0",
      preconditions: body.preconditions ?? [],
      decisionPoints: body.decisionPoints ?? [],
      verificationCriteria: body.verificationCriteria ?? [],
    });
    if (result.isFailure) {
      res.status(409).json({ error: result.error });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  update = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const body = validateBody(updateRunbookSchema, req, res);
    if (!body) return;
    const result = await this.updateRunbook.execute({ ...body, id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "INVALID_RUNBOOK" });
      return;
    }
    res.json(result.value.toJSON());
  };
}
