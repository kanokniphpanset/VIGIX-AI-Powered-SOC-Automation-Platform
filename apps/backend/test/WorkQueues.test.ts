import {
  ApprovalQueueRow,
  ApprovalStepRow,
  TicketRow,
  activeApprovalStep,
  inApprovalQueue,
  inQueue,
  queueCounts,
  sanitizeMetadata,
  ticketStage,
} from "../src/application/work/WorkQueues";
import { WorkQueries } from "../src/application/work/WorkQueries.usecases";
import { IWorkReadRepository } from "../src/application/work/ports/IWorkReadRepository";
import { INBOX_STATUSES, OPEN_WORKFLOW_STATES, autoIncidentBySeverity, displayState, inSocWorkflow, isInboxStatus, slaDueAt, slaStatus, validateTriageInput } from "../src/domain/alert/triageWorkflow";
import { GetDashboardSummaryUseCase } from "../src/application/dashboard/use-cases/GetDashboardSummary.usecase";
import { IDashboardReadRepository } from "../src/application/dashboard/ports/IDashboardReadRepository";
import { IncidentSlaService } from "../src/application/sla/IncidentSlaService";
import { ISiemRehuntPort } from "../src/application/verification/ports/ISiemRehuntPort";
import { buildWorkRoutes, buildIncidentWorkRoutes } from "../src/presentation/http/routes/work.routes";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";

const IR = { id: "u-ir", role: "IR_TEAM" };
const IR2 = { id: "u-ir2", role: "IR_TEAM" };
const SOC = { id: "u-soc", role: "SOC" };
const ADMIN = { id: "u-admin", role: "admin" };

const step = (o: Partial<ApprovalStepRow>): ApprovalStepRow => ({ id: "a", role: "IR_TEAM", status: "pending", stepOrder: 1, decidedBy: null, decidedAt: null, createdAt: "2026-09-25T00:00:00Z", ...o });

function ticket(o: Partial<TicketRow> = {}): TicketRow {
  return {
    id: "t1", incidentId: "i1", incidentTitle: "x", incidentStatus: "investigating", incidentPriority: "high", investigationNumber: 1,
    recommendationId: "r1", recommendationStepId: "s1", stepTitle: "Block IP", stepOrder: 1, actionCode: "ACT-BLOCK-SOURCE-IP", actionName: "Block Source IP",
    target: "203.0.113.9", status: "READY_FOR_EXECUTION", approvalStatus: "NOT_REQUIRED", assignedRole: "IR_TEAM", assignedTo: null, assignedToEmail: null,
    executedAt: null, completedAt: null, createdAt: "2026-09-25T00:00:00Z", updatedAt: "2026-09-25T00:00:00Z", approvals: [], verification: null,
    ...o,
  };
}

// Every ticket waits for exactly one IR_TEAM decision (two-role workflow, no approval chain).
const pendingIr = ticket({
  id: "crit", status: "PENDING_IR_DECISION", approvalStatus: "PENDING",
  approvals: [step({ id: "ap-ir", role: "IR_TEAM", status: "pending", stepOrder: 1 })],
});
// A ticket created before the two-role change (PENDING_APPROVAL) whose open step was migrated to IR_TEAM.
const legacyPending = ticket({
  id: "crit2", status: "PENDING_APPROVAL", approvalStatus: "PENDING",
  approvals: [step({ id: "ap-ir2", role: "IR_TEAM", status: "approved", stepOrder: 1 }), step({ id: "ap-ir3", role: "IR_TEAM", status: "pending", stepOrder: 2 })],
});

describe("ticketStage (derived only from stored workflow state)", () => {
  it.each([
    ["PENDING_IR_DECISION", null, "investigating", "AWAITING_IR_DECISION"],
    ["PENDING_APPROVAL", null, "investigating", "AWAITING_IR_DECISION"],
    ["MORE_EVIDENCE_REQUESTED", null, "investigating", "REJECTED"],
    ["READY_FOR_EXECUTION", null, "investigating", "READY_FOR_EXECUTION"],
    ["IN_PROGRESS", null, "investigating", "IN_PROGRESS"],
    ["COMPLETED", null, "investigating", "AWAITING_REHUNT"],
    ["COMPLETED", "RESOLVED", "resolved", "COMPLETED"],
    ["COMPLETED", "NOT_RESOLVED", "investigating", "NOT_RESOLVED"],
    ["COMPLETED", "NOT_RESOLVED", "escalated", "ESCALATED"],
    ["FAILED", null, "investigating", "FAILED"],
    ["REJECTED", null, "investigating", "REJECTED"],
  ])("%s + verification %s + incident %s -> %s", (status, result, incidentStatus, expected) => {
    const verification = result ? { id: "v", result, spreadDetected: false, verifiedAt: "x" } : null;
    expect(ticketStage({ status, verification, incidentStatus })).toBe(expected);
  });
});

describe("Ticket queues follow backend assignment, never email recipients", () => {
  it("My Work (IR) = tickets awaiting the IR decision + tickets I started that are unfinished + unstarted READY tickets", () => {
    const mine = ticket({ id: "mine", status: "IN_PROGRESS", assignedTo: IR.id });
    const mineAwaitingRehunt = ticket({ id: "m2", status: "COMPLETED", assignedTo: IR.id });
    const someoneElses = ticket({ id: "other", status: "IN_PROGRESS", assignedTo: "u-other" });
    const unclaimedIr = ticket({ id: "free" });
    const unclaimedSoc = ticket({ id: "soc", assignedRole: "SOC" });
    const mineDone = ticket({ id: "done", status: "COMPLETED", assignedTo: IR.id, verification: { id: "v", result: "RESOLVED", spreadDetected: false, verifiedAt: "x" }, incidentStatus: "resolved" });
    const rejected = ticket({ id: "rej", status: "REJECTED", approvalStatus: "REJECTED" });
    const rows = [pendingIr, mine, mineAwaitingRehunt, someoneElses, unclaimedIr, unclaimedSoc, mineDone, rejected];
    expect(rows.filter((t) => inQueue("my-work", t, IR)).map((t) => t.id)).toEqual(["crit", "mine", "m2", "free"]);
    // SOC never decides or executes: a pending decision is not SOC work.
    expect(rows.filter((t) => inQueue("my-work", t, SOC)).map((t) => t.id)).toEqual(["soc"]);
  });

  it("Awaiting decision = every ticket waiting for the IR APPROVE / REJECT (any IR analyst may decide)", () => {
    expect(inQueue("awaiting-decision", pendingIr, IR)).toBe(true);
    expect(inQueue("awaiting-decision", pendingIr, IR2)).toBe(true);
    expect(inQueue("awaiting-decision", legacyPending, IR)).toBe(true);
    expect(inQueue("awaiting-decision", ticket({ status: "READY_FOR_EXECUTION" }), IR)).toBe(false);
    expect(activeApprovalStep(pendingIr.approvals)?.id).toBe("ap-ir");
    expect(activeApprovalStep(legacyPending.approvals)?.id).toBe("ap-ir3");
  });

  it("admin never has IR work of its own", () => {
    expect(inQueue("my-work", pendingIr, ADMIN)).toBe(false);
  });

  it("counts every queue from the same rows (rejected tickets have their own queue)", () => {
    const c = queueCounts([pendingIr, legacyPending, ticket({ id: "f", status: "FAILED" }), ticket({ id: "r", status: "REJECTED" })], IR);
    expect(c).toMatchObject({ "awaiting-decision": 2, rejected: 1, failed: 1, all: 4, ready: 0 });
  });

  it("escalated queue holds tickets of escalated incidents that were not resolved", () => {
    const esc = ticket({ status: "COMPLETED", incidentStatus: "escalated", verification: { id: "v", result: "NOT_RESOLVED", spreadDetected: true, verifiedAt: "x" } });
    expect(inQueue("escalated", esc, IR)).toBe(true);
  });
});

describe("Approval queue", () => {
  const row = (o: Partial<ApprovalQueueRow>): ApprovalQueueRow => ({
    id: "a", role: "IR_TEAM", status: "pending", stepOrder: 1, reason: null, comment: null, decidedBy: null, decidedByEmail: null, decidedAt: null,
    createdAt: "x", responseId: "t", recommendationId: "r", incidentId: "i", incidentTitle: "t", incidentPriority: "critical", incidentStatus: "investigating",
    target: null, planStatus: "PENDING_IR_DECISION", stepTitle: null, actionName: null, chain: [], ...o,
  });

  it("IR (mine, pending) sees the open IR decisions; decided ones only under decided; SOC never has a decision", () => {
    expect(inApprovalQueue(row({}), IR, "mine", "pending")).toBe(true);
    expect(inApprovalQueue(row({ status: "approved" }), IR, "mine", "pending")).toBe(false);
    expect(inApprovalQueue(row({ status: "rejected" }), IR, "mine", "decided")).toBe(true);
    expect(inApprovalQueue(row({}), SOC, "mine", "pending")).toBe(false);
    // A decided historical row may still name the retired role: never "mine" for anyone now.
    expect(inApprovalQueue(row({ role: "MANAGER", status: "approved" }), IR, "mine", "decided")).toBe(false);
  });

  it("canDecide is true only for an IR_TEAM viewer on an open IR decision, never for SOC or admin", async () => {
    const repo = { approvals: async () => [row({ id: "p" }), row({ id: "d", status: "rejected" })] } as unknown as IWorkReadRepository;
    const q = new WorkQueries(repo);
    const ir = await q.approvals({ tenantId: "t", viewer: IR, scope: "all", status: "all", limit: 10, offset: 0 });
    expect(ir.items.map((i) => [i.id, i.canDecide])).toEqual([["p", true], ["d", false]]);
    expect(ir.counts).toEqual({ minePending: 1, mineWaiting: 0, mineDecided: 1 });
    const soc = await q.approvals({ tenantId: "t", viewer: SOC, scope: "all", status: "all", limit: 10, offset: 0 });
    expect(soc.items.every((i) => !i.canDecide)).toBe(true);
    const adm = await q.approvals({ tenantId: "t", viewer: ADMIN, scope: "all", status: "all", limit: 10, offset: 0 });
    expect(adm.items.every((i) => !i.canDecide)).toBe(true);
    const admMine = await q.approvals({ tenantId: "t", viewer: ADMIN, scope: "mine", status: "pending", limit: 10, offset: 0 });
    expect(admMine.total).toBe(0);
  });
});

describe("Audit sanitising", () => {
  it("drops credential-looking keys at any depth", () => {
    expect(sanitizeMetadata({ status: "SENT", smtpPassword: "x", nested: { apiKey: "k", ok: 1, list: [{ token: "t", v: 2 }] } })).toEqual({ status: "SENT", nested: { ok: 1, list: [{ v: 2 }] } });
  });
});

describe("Alert review workflow (canonical states, shared by backend and frontend)", () => {
  it("only MEDIUM / HIGH / CRITICAL enter the SOC workflow; HIGH / CRITICAL open an incident automatically", () => {
    expect(["low", "medium", "high", "critical"].map(inSocWorkflow)).toEqual([false, true, true, true]);
    expect(inSocWorkflow("LOW")).toBe(false);
    expect(["low", "medium", "high", "critical"].map(autoIncidentBySeverity)).toEqual([false, false, true, true]);
  });

  it("status filter and open states: no claim — legacy IN_TRIAGE / MONITORING alerts are still open", () => {
    expect(INBOX_STATUSES).toEqual(["needs-review", "in-incident", "closed", "all"]);
    expect(isInboxStatus("needs-review")).toBe(true);
    expect(isInboxStatus("needs-triage")).toBe(false);
    expect(OPEN_WORKFLOW_STATES).toEqual(["NEW", "IN_TRIAGE", "MONITORING"]);
  });

  it("display state: severity, workflow state and incident link are separate facts", () => {
    expect(displayState({ workflowState: "NEW", incidentId: null })).toBe("NEEDS_REVIEW");
    expect(displayState({ workflowState: "IN_TRIAGE", incidentId: null })).toBe("NEEDS_REVIEW");
    expect(displayState({ workflowState: "MONITORING", incidentId: null })).toBe("MONITORING");
    expect(displayState({ workflowState: "TRIAGED", incidentId: null })).toBe("CLOSED");
    expect(displayState({ workflowState: "TRIAGED", incidentId: "inc-1" })).toBe("IN_INCIDENT");
    expect(displayState({ workflowState: null, incidentId: null })).toBe("NEEDS_REVIEW");
  });

  it("the reason is optional for every decision", () => {
    expect(validateTriageInput({ decision: "FALSE_POSITIVE", reason: " " })).toBeNull();
    expect(validateTriageInput({ decision: "INFORMATIONAL", reason: null })).toBeNull();
    expect(validateTriageInput({ decision: "INFORMATIONAL", reason: "benign admin job" })).toBeNull();
    expect(validateTriageInput({ decision: "FALSE_POSITIVE", reason: "known scanner" })).toBeNull();
    // The incident keeps the Wazuh severity, so creating one needs nothing else.
    expect(validateTriageInput({ decision: "CREATE_INCIDENT", reason: null })).toBeNull();
  });

  it("triage SLA: due from Policy minutes; clock restarts at review; statuses", () => {
    const minutes = { CRITICAL: 15, HIGH: 30, MEDIUM: 240, LOW: 1440 };
    const received = new Date("2026-09-25T10:00:00Z");
    const due = slaDueAt({ severity: "critical", receivedAt: received, reviewAt: null, workflowState: "NEW" }, minutes)!;
    expect(due.toISOString()).toBe("2026-09-25T10:15:00.000Z");
    const reviewed = slaDueAt({ severity: "high", receivedAt: received, reviewAt: new Date("2026-09-26T08:00:00Z"), workflowState: "IN_TRIAGE" }, minutes)!;
    expect(reviewed.toISOString()).toBe("2026-09-26T08:30:00.000Z");
    expect(slaDueAt({ severity: "low", receivedAt: received, reviewAt: null, workflowState: "NEW" }, {})).toBeNull(); // no Policy target -> no SLA
    const base = { severity: "critical", closedAt: null };
    expect(slaStatus({ ...base, workflowState: "NEW" }, due, minutes, new Date("2026-09-25T10:05:00Z"))).toBe("ON_TRACK");
    expect(slaStatus({ ...base, workflowState: "NEW" }, due, minutes, new Date("2026-09-25T10:12:00Z"))).toBe("DUE_SOON");
    expect(slaStatus({ ...base, workflowState: "IN_TRIAGE" }, due, minutes, new Date("2026-09-25T10:16:00Z"))).toBe("BREACHED");
    expect(slaStatus({ ...base, workflowState: "TRIAGED", closedAt: new Date("2026-09-25T10:10:00Z") }, due, minutes, new Date())).toBe("MET");
    expect(slaStatus({ ...base, workflowState: "TRIAGED", closedAt: new Date("2026-09-25T11:00:00Z") }, due, minutes, new Date())).toBe("MISSED");
    expect(slaStatus({ ...base, workflowState: "MONITORING" }, due, minutes, new Date())).toBeNull();
  });
});

describe("Dashboard System Health is honest", () => {
  const repo = {
    counts: async () => ({}),
    openIncidents: async () => [],
    ping: async () => 4,
  } as unknown as IDashboardReadRepository;
  const sla = { forIncident: jest.fn() } as unknown as IncidentSlaService;
  const rehunt = { health: async () => ({ configured: true, reachable: true, indexPattern: "wazuh-alerts-*" }) } as unknown as ISiemRehuntPort;

  it("mock re-hunt is NOT reported as a healthy Wazuh Indexer; failing probes are DOWN; unknown stays UNKNOWN", async () => {
    const uc = new GetDashboardSummaryUseCase(repo, sla, rehunt, "mock", async () => ({ reachable: false, latencyMs: null }), [
      { key: "qdrant", label: "Qdrant", probe: async () => { throw new Error("ECONNREFUSED"); } },
      { key: "wazuh", label: "Wazuh Manager", probe: async () => ({ status: "UNKNOWN", detail: "no API", latencyMs: null }) },
    ]);
    const r = (await uc.execute({ tenantId: "t" })).value;
    const by = Object.fromEntries(r.systemHealth.map((h) => [h.key, h.status]));
    expect(by).toEqual({ backend: "UP", postgres: "UP", "ai-orchestrator": "DOWN", "wazuh-indexer": "NOT_CONFIGURED", qdrant: "DOWN", wazuh: "UNKNOWN" });
  });

  it("database ping failure -> PostgreSQL DOWN", async () => {
    const uc = new GetDashboardSummaryUseCase({ ...repo, ping: async () => { throw new Error("down"); } } as IDashboardReadRepository, sla, rehunt, "wazuh-indexer", async () => ({ reachable: true, latencyMs: 3 }));
    const r = (await uc.execute({ tenantId: "t" })).value;
    expect(r.systemHealth.find((h) => h.key === "postgres")?.status).toBe("DOWN");
    expect(r.systemHealth.find((h) => h.key === "wazuh-indexer")?.status).toBe("UP");
  });
});

describe("/api/v1/work routes", () => {
  type Layer = { route?: { path: string; methods: Record<string, boolean>; stack: { handle: (...a: unknown[]) => unknown }[] } };
  const calls: { method: string; input: unknown }[] = [];
  const queries = {
    tickets: async (input: unknown) => (calls.push({ method: "tickets", input }), { items: [] }),
    approvals: async (input: unknown) => (calls.push({ method: "approvals", input }), { items: [] }),
    incidents: async (input: unknown) => (calls.push({ method: "incidents", input }), { items: [] }),
    incidentAudit: async () => null,
    incidentAiJobs: async () => [],
  } as unknown as WorkQueries;

  async function call(router: unknown, path: string, role: string | null, query: Record<string, string> = {}, params: Record<string, string> = {}) {
    const layer = (router as { stack: Layer[] }).stack.find((l) => l.route?.path === path)!;
    const req = { header: (n: string) => (n.toLowerCase() === "authorization" && role ? `Bearer ${signToken({ id: `u-${role}`, tenantId: "tenant-1", role })}` : undefined), query, params, user: undefined as unknown };
    let status = 200;
    let body: unknown = null;
    const res = { headersSent: false, status: (s: number) => ((status = s), res), json: (b: unknown) => ((body = b), res) };
    for (const { handle } of layer.route!.stack) {
      let next = false;
      await handle(req, res, () => void (next = true));
      if (!next) break;
    }
    return { status, body };
  }

  it("requires a signed-in user; the viewer comes from the token (not the query string)", async () => {
    const router = buildWorkRoutes(queries);
    expect((await call(router, "/tickets", null)).status).toBe(401);
    calls.length = 0;
    expect((await call(router, "/tickets", "SOC", { queue: "awaiting-decision", role: "IR_TEAM" })).status).toBe(200);
    expect(calls[0].input).toMatchObject({ tenantId: "tenant-1", viewer: { id: "u-SOC", role: "SOC" }, queue: "awaiting-decision" });
  });

  it("rejects unknown queues / filters with 400", async () => {
    const router = buildWorkRoutes(queries);
    expect((await call(router, "/tickets", "IR_TEAM", { queue: "everything" })).status).toBe(400);
    expect((await call(router, "/approvals", "IR_TEAM", { scope: "others" })).status).toBe(400);
  });

  it("incident audit of an unknown incident -> 404", async () => {
    const router = buildIncidentWorkRoutes(queries);
    expect((await call(router, "/:incidentId/audit", "SOC", {}, { incidentId: "nope" })).status).toBe(404);
  });
});

describe("Manual verification cannot resolve (re-hunt only)", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { wouldResolve } = require("../src/presentation/http/controllers/VerificationController");
  it("a hand-entered clean result would resolve -> refused at the HTTP layer; any NOT_RESOLVED signal is allowed", () => {
    expect(wouldResolve({ threatContained: true, matchingEvents: 0 })).toBe(true);
    expect(wouldResolve({ threatContained: true, matchingEvents: 2 })).toBe(false);
    expect(wouldResolve({ threatContained: false, matchingEvents: 0 })).toBe(false);
    expect(wouldResolve({ threatContained: true, matchingEvents: 0, spreadDetected: true })).toBe(false);
    expect(wouldResolve({ threatContained: true, matchingEvents: 0, iocRecurrence: true })).toBe(false);
  });
});
