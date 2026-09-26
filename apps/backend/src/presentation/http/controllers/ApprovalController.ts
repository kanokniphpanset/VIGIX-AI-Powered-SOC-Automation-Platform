import { Request, Response } from "express";
import { RequestApprovalUseCase } from "../../../application/approval/use-cases/RequestApproval.usecase";
import { DecideApprovalUseCase } from "../../../application/approval/use-cases/DecideApproval.usecase";
import { GetApprovalUseCase } from "../../../application/approval/use-cases/GetApproval.usecase";
import { ListApprovalsByRecommendationUseCase } from "../../../application/approval/use-cases/ListApprovalsByRecommendation.usecase";
import { requestApprovalSchema, decideApprovalSchema } from "../../../application/approval/dto/ApprovalDto";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

export class ApprovalController {
  constructor(
    private readonly requestApproval: RequestApprovalUseCase,
    private readonly decideApproval: DecideApprovalUseCase,
    private readonly getApproval: GetApprovalUseCase,
    private readonly listApprovalsByRecommendation: ListApprovalsByRecommendationUseCase
  ) {}

  listByRecommendation = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const approvals = await this.listApprovalsByRecommendation.execute({ recommendationId: req.params.id, tenantId });
    res.json({ items: approvals.map((a) => a.toJSON()) });
  };

  request = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const body = validateBody(requestApprovalSchema, req, res);
    if (!body) return;

    const result = await this.requestApproval.execute({ recommendationId: body.recommendationId, responseId: body.responseId, tenantId });
    if (result.isFailure) {
      const statusCode = result.error === "RECOMMENDATION_NOT_FOUND" || result.error === "RESPONSE_NOT_FOUND" ? 404 : 409;
      res.status(statusCode).json({ error: result.error });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const result = await this.getApproval.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "APPROVAL_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };

  private decide = (status: "approved" | "rejected") =>
    async (req: Request, res: Response): Promise<void> => {
      const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
      const body = validateBody(decideApprovalSchema, req, res);
      if (!body) return;
      if (!req.user) {
        res.status(401).json({ error: "UNAUTHENTICATED" });
        return;
      }

      const result = await this.decideApproval.execute({
        approvalId: req.params.id,
        tenantId,
        status,
        decidedBy: req.user.id,
        decidedByRole: req.user.role,
        comment: body.comment ?? null,
      });

      if (result.isFailure) {
        const statusCode =
          result.error === "NOT_FOUND" ? 404 : result.error === "ROLE_MISMATCH" || result.error === "ADMIN_NOT_APPROVER" ? 403 : result.error === "NOTE_REQUIRED" ? 422 : 409;
        res.status(statusCode).json({ error: result.error });
        return;
      }
      res.json(result.value.toJSON());
    };

  approve = this.decide("approved");
  reject = this.decide("rejected");
}
