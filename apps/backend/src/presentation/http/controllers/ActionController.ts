import { Request, Response } from "express";
import { CreateActionUseCase } from "../../../application/action/use-cases/CreateAction.usecase";
import { UpdateActionUseCase } from "../../../application/action/use-cases/UpdateAction.usecase";
import { EnableActionUseCase } from "../../../application/action/use-cases/EnableAction.usecase";
import { DisableActionUseCase } from "../../../application/action/use-cases/DisableAction.usecase";
import { GetActionUseCase } from "../../../application/action/use-cases/GetAction.usecase";
import { ListActionsUseCase } from "../../../application/action/use-cases/ListActions.usecase";
import { createActionSchema, updateActionSchema } from "../../../application/action/dto/ActionDto";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

export class ActionController {
  constructor(
    private readonly createAction: CreateActionUseCase,
    private readonly updateAction: UpdateActionUseCase,
    private readonly enableAction: EnableActionUseCase,
    private readonly disableAction: DisableActionUseCase,
    private readonly getAction: GetActionUseCase,
    private readonly listActions: ListActionsUseCase
  ) {}

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const actions = await this.listActions.execute({ tenantId });
    res.json({ items: actions.map((a) => a.toJSON()) });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const result = await this.getAction.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "ACTION_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };

  create = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const body = validateBody(createActionSchema, req, res);
    if (!body) return;
    const result = await this.createAction.execute({
      ...body,
      tenantId,
      defaultApprovalRequired: body.defaultApprovalRequired ?? false,
    });
    if (result.isFailure) {
      res.status(409).json({ error: result.error });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  update = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const body = validateBody(updateActionSchema, req, res);
    if (!body) return;
    const result = await this.updateAction.execute({ ...body, id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "ACTION_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };

  enable = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const result = await this.enableAction.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "ACTION_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };

  disable = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const result = await this.disableAction.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "ACTION_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };
}
