import { Request, Response, Router } from "express";
import { authenticate } from "../middlewares/auth.middleware";
import { WorkQueries } from "../../../application/work/WorkQueries.usecases";
import { ApprovalScope, ApprovalStatusFilter, TICKET_QUEUES, TicketQueue } from "../../../application/work/WorkQueues";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

const qs = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);
const list = (v: unknown): string[] | undefined => qs(v)?.split(",").map((s) => s.trim()).filter(Boolean);
/** Express 4 does not catch rejected async handlers: a read failure answers 500 instead of hanging the request. */
const safe = (fn: (req: Request, res: Response) => Promise<void>) => (req: Request, res: Response) =>
  fn(req, res).catch((err: unknown) => {
    console.error("[work] read failed", err instanceof Error ? err.message : err);
    if (!res.headersSent) res.status(500).json({ error: "READ_FAILED" });
  });
const int = (v: unknown, fallback: number, max: number) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.min(Math.floor(n), max) : fallback;
};

/**
 * Mounted at /api/v1/work. Read-only role workspaces (any signed-in role; the viewer comes from the JWT, never from the
 * query string). Actions stay on their existing, role-gated routes (approvals, responses, verifications, triage).
 *   GET /tickets?queue=my-work|awaiting-decision|ready|in-progress|awaiting-rehunt|completed|rejected|failed|escalated|all
 *   GET /approvals?scope=mine|all&status=pending|waiting|decided|all
 *   GET /incidents?status=a,b&priority=critical&search=
 *   GET /iocs                — threat-intelligence library: indicators across all incidents, most-sighted first
 */
export function buildWorkRoutes(queries: WorkQueries): Router {
  const router = Router();

  router.get("/tickets", authenticate, safe(async (req: Request, res: Response) => {
    const queue = (qs(req.query.queue) ?? "all") as TicketQueue;
    if (!TICKET_QUEUES.includes(queue)) {
      res.status(400).json({ error: "INVALID_QUEUE", allowed: TICKET_QUEUES });
      return;
    }
    const user = req.user!;
    res.json(
      await queries.tickets({
        tenantId: user.tenantId ?? DEFAULT_TENANT_ID,
        viewer: { id: user.id, role: user.role },
        queue,
        incidentId: qs(req.query.incidentId),
        limit: int(req.query.limit, 25, 200),
        offset: int(req.query.offset, 0, 100_000),
      })
    );
  }));

  router.get("/approvals", authenticate, safe(async (req: Request, res: Response) => {
    const scope = (qs(req.query.scope) ?? "mine") as ApprovalScope;
    const status = (qs(req.query.status) ?? "pending") as ApprovalStatusFilter;
    if (!["mine", "all"].includes(scope) || !["pending", "waiting", "decided", "all"].includes(status)) {
      res.status(400).json({ error: "INVALID_FILTER" });
      return;
    }
    const user = req.user!;
    res.json(
      await queries.approvals({
        tenantId: user.tenantId ?? DEFAULT_TENANT_ID,
        viewer: { id: user.id, role: user.role },
        scope,
        status,
        limit: int(req.query.limit, 50, 200),
        offset: int(req.query.offset, 0, 100_000),
      })
    );
  }));

  router.get("/incidents", authenticate, safe(async (req: Request, res: Response) => {
    res.json(
      await queries.incidents({
        tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID,
        filters: {
          status: list(req.query.status),
          priority: list(req.query.priority),
          search: qs(req.query.search),
          limit: int(req.query.limit, 25, 200),
          offset: int(req.query.offset, 0, 100_000),
        },
      })
    );
  }));

  router.get("/iocs", authenticate, safe(async (req: Request, res: Response) => {
    res.json(await queries.iocLibrary({ tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID, limit: int(req.query.limit, 500, 1000) }));
  }));

  return router;
}

/**
 * Mounted at /api/v1/incidents (read-only, any signed-in role):
 *   GET /:incidentId/audit    — the incident's audit trail (audit_logs of the incident and its alerts, recommendations,
 *                               tickets, approvals, verifications) merged with its timeline; credentials never included.
 *   GET /:incidentId/ai-jobs  — the incident's AI analysis jobs (DB queue rows: status, trigger, attempt, error).
 *   GET /:incidentId/similar  — closed incidents similar to it (shared IOC / rule / technique / host), with the reasons
 *                               and how each was handled; deterministic, no AI.
 */
export function buildIncidentWorkRoutes(queries: WorkQueries): Router {
  const router = Router();
  router.get("/:incidentId/audit", authenticate, safe(async (req: Request, res: Response) => {
    const items = await queries.incidentAudit({ tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID, incidentId: req.params.incidentId, limit: int(req.query.limit, 300, 1000) });
    if (!items) {
      res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
      return;
    }
    res.json({ items });
  }));
  router.get("/:incidentId/ai-jobs", authenticate, safe(async (req: Request, res: Response) => {
    const items = await queries.incidentAiJobs({ tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID, incidentId: req.params.incidentId });
    if (!items) {
      res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
      return;
    }
    res.json({ items });
  }));
  router.get("/:incidentId/similar", authenticate, safe(async (req: Request, res: Response) => {
    const items = await queries.similarCases({ tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID, incidentId: req.params.incidentId, limit: int(req.query.limit, 5, 20) });
    if (!items) {
      res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
      return;
    }
    res.json({ items });
  }));
  return router;
}
