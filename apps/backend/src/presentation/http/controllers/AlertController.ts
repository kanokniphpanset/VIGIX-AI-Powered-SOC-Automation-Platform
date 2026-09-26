import { Request, Response } from "express";
import { ListAlertsUseCase } from "../../../application/alert/use-cases/ListAlerts.usecase";
import { GetAlertByIdUseCase } from "../../../application/alert/use-cases/GetAlertById.usecase";
import { IngestAlertFromSiemUseCase } from "../../../application/alert/use-cases/IngestAlertFromSiem.usecase";
import { GetAlertViewUseCase, ListAlertInboxUseCase } from "../../../application/alert/use-cases/AlertInbox.usecases";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";
const q = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);
const date = (v: unknown): Date | undefined => {
  const d = q(v) ? new Date(q(v)!) : undefined;
  return d && !Number.isNaN(d.getTime()) ? d : undefined;
};

/**
 * AlertController — presentation layer (Ring 4).
 * Translates HTTP <-> use-case calls. Contains no business logic.
 */
export class AlertController {
  constructor(
    private readonly listAlerts: ListAlertsUseCase,
    private readonly getAlertById: GetAlertByIdUseCase,
    private readonly ingestAlert: IngestAlertFromSiemUseCase,
    private readonly listInbox?: ListAlertInboxUseCase,
    private readonly getAlertView?: GetAlertViewUseCase
  ) {}

  /** GET /alerts/inbox — Alert Inbox read model (MEDIUM / HIGH / CRITICAL; summary + SLA + incident link), filterable. */
  inbox = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.listInbox!.execute({
      tenantId: req.user?.tenantId ?? tenantId,
      filters: {
        status: q(req.query.status),
        source: q(req.query.source),
        sort: q(req.query.sort),
        search: q(req.query.search),
        severity: q(req.query.severity),
        incident: q(req.query.incident),
        mitre: q(req.query.mitre),
        attackType: q(req.query.attackType),
        scenario: q(req.query.scenario),
        agent: q(req.query.agent),
        from: date(req.query.from),
        to: date(req.query.to),
        limit: req.query.limit ? Math.min(Number(req.query.limit) || 50, 200) : 50,
        offset: req.query.offset ? Number(req.query.offset) || 0 : 0,
      },
    });
    res.json(result.value);
  };

  /** GET /alerts/:id/view — Alert Detail: summary, raw Wazuh payload, IOCs, incident. */
  view = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const result = await this.getAlertView!.execute({ tenantId, alertId: req.params.id });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value);
  };

  list = async (req: Request, res: Response): Promise<void> => {
    // TODO: replace with tenantId from authenticated session once auth middleware exists
    const tenantId =
      req.user?.tenantId ?? DEFAULT_TENANT_ID;

    const limit = req.query.limit ? Number(req.query.limit) : 25;
    const offset = req.query.offset ? Number(req.query.offset) : 0;
    const unlinked = req.query.unlinked === "true";

    const result = await this.listAlerts.execute({
      tenantId,
      limit,
      offset,
      unlinked,
    });

    res.json({
      items: result.value.items.map((a) => a.toJSON()),
      total: result.value.total,
      limit: result.value.limit,
      offset: result.value.offset,
    });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId =
      req.user?.tenantId ?? DEFAULT_TENANT_ID;

    const result = await this.getAlertById.execute({
      id: req.params.id,
      tenantId,
    });

    if (result.isFailure) {
      res.status(404).json({ error: "Alert not found" });
      return;
    }

    res.json(result.value.toJSON());
  };

  ingest = async (req: Request, res: Response): Promise<void> => {
    const tenantId =
      req.user?.tenantId ?? DEFAULT_TENANT_ID;

    const result = await this.ingestAlert.execute({
      tenantId,
      externalAlertId: req.body.externalAlertId,
      siemSource: req.body.siemSource,
      severity: req.body.severity,
      receivedAt: new Date(req.body.receivedAt),
      rawPayload: req.body.rawPayload,
    });

    // 202: stored + incident opened + AI queued; the analysis runs in the background worker.
    res.status(202).json({
      alert: result.value.alert.toJSON(),
      incidentId: result.value.incidentId,
      aiJob: result.value.aiJob,
      duplicate: result.value.duplicate,
      triageRequired: result.value.triageRequired,
    });
  };
}