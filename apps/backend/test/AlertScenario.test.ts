import type { NextFunction, Request, Response } from "express";
import { Alert } from "../src/domain/alert/entities/Alert.entity";
import { ATTACK_SCENARIOS, findAttackScenario } from "../src/domain/alert/attackScenarios";
import { AlertScenarioTagRecord, IAlertScenarioRepository } from "../src/domain/alert/repositories/IAlertScenarioRepository";
import { SetAlertScenarioUseCase } from "../src/application/alert/use-cases/AlertScenario.usecases";
import { GetAlertViewUseCase, ListAlertInboxUseCase } from "../src/application/alert/use-cases/AlertInbox.usecases";
import { IAlertInboxQuery, InboxQueryParams } from "../src/application/alert/ports/IAlertInboxQuery";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { buildAlertScenarioRoutes } from "../src/presentation/http/routes/alert-scenario.routes";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";

const T = "00000000-0000-0000-0000-000000000001";
const wazuh = (rule: string, host: string, srcip: string, user = "labuser") => ({
  id: `wz-${rule}-${srcip}`,
  rule: { id: rule, description: rule === "5763" ? "sshd: brute force trying to get access to the system. Authentication failed." : "other", level: 10, mitre: { id: ["T1110"] } },
  agent: { id: "001", name: host, ip: "172.19.0.5" },
  data: { srcip, dstuser: user },
});
const alert = (id: string, payload: Record<string, unknown>, min: number) =>
  Alert.create({ id, tenantId: T, externalAlertId: `ext-${id}`, siemSource: "wazuh", rawPayload: payload, severity: "medium", status: "received", receivedAt: new Date(Date.UTC(2026, 8, 23, 22, min)), createdAt: new Date() } as never);

const ALERTS = [
  alert("a1", wazuh("5763", "vigix-lab-ubuntu", "172.31.250.50"), 10),
  alert("a2", wazuh("5763", "vigix-lab-ubuntu", "172.31.250.50", "admin"), 15),
  alert("a3", wazuh("5402", "WKS-FIN-07", "10.0.0.8"), 20),
];

class MemoryTags implements IAlertScenarioRepository {
  rows = new Map<string, AlertScenarioTagRecord>();
  async findByAlertIds(ids: string[]) { return new Map([...this.rows].filter(([k]) => ids.includes(k))); }
  async set(alertId: string, _t: string, scenarioId: string, taggedBy: string) { const r = { alertId, scenarioId, taggedBy, taggedAt: new Date() }; this.rows.set(alertId, r); return r; }
  async clear(alertId: string) { this.rows.delete(alertId); }
}

/**
 * The inbox query itself runs in SQL (see AlertInboxQuery.db.test.ts for the real filtering / join). Here the
 * database port is a recorder that returns every alert with its scenario tag, so these tests check what the use case
 * ASKS the database for (scenario ids from the catalog) and what it returns per item.
 */
function world() {
  const alerts = { findAll: async () => ALERTS, findById: async (id: string) => ALERTS.find((a) => a.id === id) ?? null } as never;
  const incidents = { findLinkedIncidents: async () => new Map(), findByIds: async () => [] } as never;
  const tags = new MemoryTags();
  const audits: { action: string; actor: string; entityId: string; metadata: Record<string, unknown> }[] = [];
  const audit = { record: async (e: never) => void audits.push(e) } as unknown as AuditLogger;
  const queries: InboxQueryParams[] = [];
  const query: IAlertInboxQuery = {
    query: async (params) => {
      queries.push(params);
      return { rows: ALERTS.map((a) => ({ alert: a, incident: null, scenarioId: tags.rows.get(a.id)?.scenarioId ?? null, slaDueAt: null })), total: ALERTS.length };
    },
  };
  const sla = { triageSlaMinutes: async () => ({}) };
  const inbox = new ListAlertInboxUseCase(query, sla);
  const asked = async (filters: Record<string, string>) => {
    await inbox.execute({ tenantId: T, filters });
    return queries[queries.length - 1];
  };
  return { tags, audits, asked, inbox, set: new SetAlertScenarioUseCase(alerts, tags, audit), view: new GetAlertViewUseCase(alerts, incidents, sla, tags) };
}

describe("Attack scenario catalog", () => {
  test("10 scenarios, 5 attack types × 2 cases, unique ids", () => {
    expect(ATTACK_SCENARIOS.map((s) => s.id)).toEqual(["ATK-01", "ATK-02", "ATK-03", "ATK-04", "ATK-05", "ATK-06", "ATK-07", "ATK-08", "ATK-09", "ATK-10"]);
    const byType = ATTACK_SCENARIOS.reduce<Record<string, number>>((m, s) => ({ ...m, [s.attackType]: (m[s.attackType] ?? 0) + 1 }), {});
    expect(Object.values(byType)).toEqual([2, 2, 2, 2, 2]);
    expect(findAttackScenario("ATK-02")?.caseName).toBe("Brute Force + Multiple Accounts");
    expect(findAttackScenario("nope")).toBeNull();
  });
});

describe("Labelling a real alert with a scenario", () => {
  test("sets, replaces and clears the label, audited with the previous value; the alert itself is untouched", async () => {
    const w = world();
    const before = JSON.stringify(ALERTS[0].rawPayload);
    expect((await w.set.execute({ tenantId: T, alertId: "a1", scenarioId: "ATK-02", actor: "soc-1" })).value.scenario?.id).toBe("ATK-02");
    await w.set.execute({ tenantId: T, alertId: "a1", scenarioId: "ATK-01", actor: "soc-1" });
    await w.set.execute({ tenantId: T, alertId: "a1", scenarioId: null, actor: "soc-1" });
    expect(w.tags.rows.size).toBe(0);
    expect(w.audits.map((a) => [a.action, a.metadata.previousScenarioId, a.metadata.scenarioId])).toEqual([
      ["ALERT_SCENARIO_TAGGED", null, "ATK-02"],
      ["ALERT_SCENARIO_TAGGED", "ATK-02", "ATK-01"],
      ["ALERT_SCENARIO_CLEARED", "ATK-01", null],
    ]);
    expect(JSON.stringify(ALERTS[0].rawPayload)).toBe(before);
  });

  test("unknown alert or unknown scenario is rejected and changes nothing", async () => {
    const w = world();
    expect((await w.set.execute({ tenantId: T, alertId: "missing", scenarioId: "ATK-01", actor: "u" })).error).toBe("ALERT_NOT_FOUND");
    expect((await w.set.execute({ tenantId: T, alertId: "a1", scenarioId: "ATK-99", actor: "u" })).error).toBe("UNKNOWN_SCENARIO");
    expect(w.tags.rows.size).toBe(0);
    expect(w.audits).toHaveLength(0);
  });
});

describe("Alert Inbox search / filter by scenario (real alerts only)", () => {
  test("attack type / case (id or name) / search are resolved to catalog scenario ids for the database query", async () => {
    const w = world();
    expect((await w.asked({ attackType: "ssh brute force" })).scenarioIds).toEqual(["ATK-01", "ATK-02"]);
    expect((await w.asked({ scenario: "ATK-05" })).scenarioIds).toEqual(["ATK-05"]);
    expect((await w.asked({ scenario: "Unauthorized Sudo Attempt" })).scenarioIds).toEqual(["ATK-05"]);
    expect((await w.asked({ attackType: "SSH Brute Force", scenario: "ATK-05" })).scenarioIds).toEqual([]); // nothing can match
    expect((await w.asked({ agent: "vigix-lab-ubuntu" })).agent).toBe("vigix-lab-ubuntu");
    const s = await w.asked({ search: "repeated failed login" });
    expect(s.search).toBe("repeated failed login");
    expect(s.searchScenarioIds).toEqual(["ATK-01"]);
    expect((await w.asked({ search: "privilege / sudo" })).searchScenarioIds).toContain("ATK-05");
    const none = await w.asked({});
    expect(none.scenarioIds).toBeUndefined();
    expect(none.status).toBe("all"); // default: every MEDIUM / HIGH / CRITICAL alert (LOW is excluded in SQL)
    expect(none.sort).toBe("urgency");
  });

  test("items and the alert detail carry the scenario (or null)", async () => {
    const w = world();
    await w.set.execute({ tenantId: T, alertId: "a1", scenarioId: "ATK-01", actor: "u" });
    const items = (await w.inbox.execute({ tenantId: T, filters: {} })).value.items;
    expect(items.find((i) => i.id === "a1")?.scenario).toMatchObject({ id: "ATK-01", attackType: "SSH Brute Force", caseName: "Repeated Failed Login" });
    expect(items.find((i) => i.id === "a2")?.scenario).toBeNull();
    expect((await w.view.execute({ tenantId: T, alertId: "a1" })).value.alert.scenario?.id).toBe("ATK-01");
  });
});

describe("Route gate: labelling is a triage (SOC) action", () => {
  const calls: string[] = [];
  const router = buildAlertScenarioRoutes({ execute: async () => (calls.push("set"), { isFailure: false, value: { alertId: "a1", scenario: null } }) } as never) as unknown as {
    stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: (req: Request, res: Response, next: NextFunction) => unknown }[] } }[];
  };
  async function call(method: "get" | "put", path: string, role: string | null) {
    const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method])!;
    const req = { header: (n: string) => (n.toLowerCase() === "authorization" && role ? `Bearer ${signToken({ id: `u-${role}`, tenantId: T, role })}` : undefined), params: { id: "a1" }, body: { scenarioId: "ATK-01" } } as unknown as Request;
    let status = 200;
    let body: unknown;
    const res = { status: (s: number) => ((status = s), res), json: (b: unknown) => ((body = b), res) } as unknown as Response;
    for (const { handle } of layer.route!.stack) {
      let next = false;
      await handle(req, res, () => void (next = true));
      if (!next) break;
    }
    return { status, body };
  }

  test("SOC and admin may label; IR_TEAM, MANAGER and anonymous may not; any signed-in role reads the catalog", async () => {
    expect((await call("put", "/:id/scenario", "SOC")).status).toBe(200);
    expect((await call("put", "/:id/scenario", "admin")).status).toBe(200);
    expect((await call("put", "/:id/scenario", "IR_TEAM")).status).toBe(403);
    expect((await call("put", "/:id/scenario", "MANAGER")).status).toBe(403);
    expect((await call("put", "/:id/scenario", null)).status).toBe(401);
    expect(calls).toEqual(["set", "set"]);
    const catalog = await call("get", "/scenarios", "MANAGER");
    expect(catalog.status).toBe(200);
    expect((catalog.body as { items: unknown[] }).items).toHaveLength(10);
  });
});
