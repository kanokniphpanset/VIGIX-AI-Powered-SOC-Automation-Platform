import { Request, Response } from "express";
import { ListAlertsUseCase } from "../../../application/alert/use-cases/ListAlerts.usecase";
import { GetAlertByIdUseCase } from "../../../application/alert/use-cases/GetAlertById.usecase";

/**
 * AlertController — presentation layer (Ring 4).
 * Translates HTTP <-> use-case calls. Contains no business logic.
 */
export class AlertController {
  constructor(
    private readonly listAlerts: ListAlertsUseCase,
    private readonly getAlertById: GetAlertByIdUseCase
  ) {}

  list = async (req: Request, res: Response): Promise<void> => {
    // TODO: replace with tenantId from authenticated session once auth middleware exists
    const tenantId = (req.query.tenantId as string) ?? "00000000-0000-0000-0000-000000000001";
    const limit = req.query.limit ? Number(req.query.limit) : 25;
    const offset = req.query.offset ? Number(req.query.offset) : 0;

    const result = await this.listAlerts.execute({ tenantId, limit, offset });

    res.json({
      items: result.value.items.map((a) => a.toJSON()),
      total: result.value.total,
      limit: result.value.limit,
      offset: result.value.offset,
    });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? "00000000-0000-0000-0000-000000000001";
    const result = await this.getAlertById.execute({ id: req.params.id, tenantId });

    if (result.isFailure) {
      res.status(404).json({ error: "Alert not found" });
      return;
    }
    res.json(result.value.toJSON());
  };
}
