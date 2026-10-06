import { authenticatedTenant } from "../middlewares/auth.middleware";
import { Request, Response } from "express";
import { GetDashboardSummaryUseCase } from "../../../application/dashboard/use-cases/GetDashboardSummary.usecase";
import { isReportWindow } from "../../../application/dashboard/reportWindow";


/** GET /api/v1/dashboard/summary — operations dashboard read model (real data, read-only). */
export class DashboardController {
  constructor(private readonly getSummary: GetDashboardSummaryUseCase) {}

  summary = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const days = Math.min(Math.max(Number(req.query.days) || 14, 1), 90);
    // Report window: prefer `period` (daily/weekly/1m/3m) — the backend computes its start instant itself.
    const period = isReportWindow(req.query.period) ? req.query.period : null;
    // `since` (ISO instant) stays supported as an override/back-compat; unparseable or future values are ignored.
    const sinceRaw = typeof req.query.since === "string" ? new Date(req.query.since) : null;
    const since = sinceRaw && !Number.isNaN(sinceRaw.getTime()) && sinceRaw.getTime() <= Date.now() ? sinceRaw : null;
    const result = await this.getSummary.execute({ tenantId, days, period, since });
    res.json(result.value);
  };
}
