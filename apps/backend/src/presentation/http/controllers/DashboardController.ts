import { Request, Response } from "express";
import { GetDashboardSummaryUseCase } from "../../../application/dashboard/use-cases/GetDashboardSummary.usecase";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

/** GET /api/v1/dashboard/summary — operations dashboard read model (real data, read-only). */
export class DashboardController {
  constructor(private readonly getSummary: GetDashboardSummaryUseCase) {}

  summary = async (req: Request, res: Response): Promise<void> => {
    const tenantId = (req.query.tenantId as string) ?? DEFAULT_TENANT_ID;
    const days = Math.min(Math.max(Number(req.query.days) || 14, 1), 90);
    // Optional report window start (ISO instant); unparseable or future values are ignored (= all time).
    const sinceRaw = typeof req.query.since === "string" ? new Date(req.query.since) : null;
    const since = sinceRaw && !Number.isNaN(sinceRaw.getTime()) && sinceRaw.getTime() <= Date.now() ? sinceRaw : null;
    const result = await this.getSummary.execute({ tenantId, days, since });
    res.json(result.value);
  };
}
