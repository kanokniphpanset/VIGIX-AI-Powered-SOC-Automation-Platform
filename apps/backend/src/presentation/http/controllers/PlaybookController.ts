import { authenticatedTenant } from "../middlewares/auth.middleware";
import { Request, Response } from "express";
import { CreatePlaybookUseCase } from "../../../application/playbook/use-cases/CreatePlaybook.usecase";
import { UpdatePlaybookUseCase } from "../../../application/playbook/use-cases/UpdatePlaybook.usecase";
import { GetPlaybookUseCase } from "../../../application/playbook/use-cases/GetPlaybook.usecase";
import { ListPlaybooksUseCase } from "../../../application/playbook/use-cases/ListPlaybooks.usecase";
import { createPlaybookSchema, updatePlaybookSchema } from "../../../application/playbook/dto/PlaybookDto";
import { validateBody } from "../validators/validateBody";
import { DeletePlaybookUseCase } from "../../../application/playbook/use-cases/DeletePlaybook.usecase";
import { z } from "zod";

const deletePlaybookSchema = z.object({ reason: z.string().trim().max(2000).optional() }).strict();


export class PlaybookController {
  constructor(
    private readonly createPlaybook: CreatePlaybookUseCase,
    private readonly updatePlaybook: UpdatePlaybookUseCase,
    private readonly getPlaybook: GetPlaybookUseCase,
    private readonly listPlaybooks: ListPlaybooksUseCase,
    private readonly deletePlaybook?: DeletePlaybookUseCase
  ) {}

  /** DELETE /:id — optional reason; actor from the JWT; audited with a copy of the playbook. 409 when executions use it. */
  remove = async (req: Request, res: Response): Promise<void> => {
    if (!this.deletePlaybook) {
      res.status(501).json({ error: "NOT_IMPLEMENTED" });
      return;
    }
    const tenantId = authenticatedTenant(req);
    const body = validateBody(deletePlaybookSchema, req, res);
    if (!body) return;
    const result = await this.deletePlaybook.execute({ id: req.params.id, tenantId, actor: req.user?.id, reason: body.reason || null });
    if (result.isFailure) {
      if (result.error === "IN_USE") res.status(409).json({ error: "PLAYBOOK_IN_USE" });
      else res.status(404).json({ error: "PLAYBOOK_NOT_FOUND" });
      return;
    }
    res.json({ deleted: true, ...result.value });
  };

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const playbooks = await this.listPlaybooks.execute({ tenantId });
    res.json({ items: playbooks.map((p) => p.toJSON()) });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const result = await this.getPlaybook.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "PLAYBOOK_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };

  // Mutations: tenant and actor come from the verified JWT (never from the query string), for the audit record.
  create = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const body = validateBody(createPlaybookSchema, req, res);
    if (!body) return;
    const result = await this.createPlaybook.execute({
      ...body,
      tenantId,
      actor: req.user?.id,
      version: body.version ?? "1.0",
      status: body.status ?? "ACTIVE",
    });
    if (result.isFailure) {
      res.status(409).json({ error: result.error });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  update = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const body = validateBody(updatePlaybookSchema, req, res);
    if (!body) return;
    const result = await this.updatePlaybook.execute({ ...body, id: req.params.id, tenantId, actor: req.user?.id });
    if (result.isFailure) {
      res.status(404).json({ error: "PLAYBOOK_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };
}
