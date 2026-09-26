import { Request, Response } from "express";
import { CreateResponsePlanUseCase } from "../../../application/response/use-cases/CreateResponsePlan.usecase";
import { StartResponseUseCase } from "../../../application/response/use-cases/StartResponse.usecase";
import { CompleteResponseUseCase } from "../../../application/response/use-cases/CompleteResponse.usecase";
import { FailResponseUseCase } from "../../../application/response/use-cases/FailResponse.usecase";
import { GetResponseUseCase } from "../../../application/response/use-cases/GetResponse.usecase";
import { ListResponsePlansUseCase } from "../../../application/response/use-cases/ListResponsePlans.usecase";
import { createResponsePlanSchema, completeResponseSchema, failResponseSchema } from "../../../application/response/dto/ResponsePlanDto";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

const ERROR_STATUS: Record<string, number> = {
  RECOMMENDATION_NOT_FOUND: 404,
  STEP_NOT_FOUND: 404,
  STEP_HAS_NO_ACTION: 422,
  NOT_FOUND: 404,
  APPROVAL_PENDING: 409,
  APPROVAL_REJECTED: 409,
  INVALID_STATE: 409,
  TICKET_ALREADY_EXISTS: 409,
};

export class ResponseController {
  constructor(
    private readonly createResponsePlan: CreateResponsePlanUseCase,
    private readonly startResponse: StartResponseUseCase,
    private readonly completeResponse: CompleteResponseUseCase,
    private readonly failResponse: FailResponseUseCase,
    private readonly getResponse: GetResponseUseCase,
    private readonly listResponsePlans: ListResponsePlansUseCase
  ) {}

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const limit = req.query.limit ? Number(req.query.limit) : 25;
    const offset = req.query.offset ? Number(req.query.offset) : 0;

    const incidentId = typeof req.query.incidentId === "string" && req.query.incidentId ? req.query.incidentId : undefined;
    const result = await this.listResponsePlans.execute({ tenantId, limit, offset, incidentId });

    res.json({
      items: result.value.items.map((r) => r.toJSON()),
      total: result.value.total,
      limit: result.value.limit,
      offset: result.value.offset,
    });
  };

  create = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const body = validateBody(createResponsePlanSchema, req, res);
    if (!body) return;

    const result = await this.createResponsePlan.execute({ ...body, tenantId });
    if (result.isFailure) {
      res.status(ERROR_STATUS[result.error] ?? 400).json({ error: result.error });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const result = await this.getResponse.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "RESPONSE_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };

  start = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.startResponse.execute({ responseId: req.params.id, tenantId, startedBy: req.user.id });
    if (result.isFailure) {
      res.status(ERROR_STATUS[result.error] ?? 400).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };

  complete = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const body = validateBody(completeResponseSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.completeResponse.execute({
      responseId: req.params.id,
      tenantId,
      completedBy: req.user.id,
      executionResult: body.executionResult,
    });
    if (result.isFailure) {
      res.status(ERROR_STATUS[result.error] ?? 400).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };

  fail = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const body = validateBody(failResponseSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.failResponse.execute({
      responseId: req.params.id,
      tenantId,
      failedBy: req.user.id,
      executionResult: body.executionResult,
    });
    if (result.isFailure) {
      res.status(ERROR_STATUS[result.error] ?? 400).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };
}
