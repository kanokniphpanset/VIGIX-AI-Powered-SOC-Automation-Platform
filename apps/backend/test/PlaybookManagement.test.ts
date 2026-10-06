import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildPlaybookRoutes } from "../src/presentation/http/routes/playbook.routes";
import { PlaybookController } from "../src/presentation/http/controllers/PlaybookController";
import { CreatePlaybookUseCase } from "../src/application/playbook/use-cases/CreatePlaybook.usecase";
import { UpdatePlaybookUseCase } from "../src/application/playbook/use-cases/UpdatePlaybook.usecase";
import { GetPlaybookUseCase } from "../src/application/playbook/use-cases/GetPlaybook.usecase";
import { DeletePlaybookUseCase } from "../src/application/playbook/use-cases/DeletePlaybook.usecase";
import { ListPlaybooksUseCase } from "../src/application/playbook/use-cases/ListPlaybooks.usecase";
import { Playbook } from "../src/domain/playbook/entities/Playbook.entity";
import { CreatePlaybookData, IPlaybookRepository, UpdatePlaybookData } from "../src/domain/playbook/repositories/IPlaybookRepository";
import { PlaybookSelector } from "../src/application/recommendation/services/PlaybookSelector";

/**
 * Knowledge -> Playbooks is human-controlled process configuration: SOC, IR_TEAM and admin create / edit / activate /
 * deactivate; any other role only reads. Every change is audited with the actor. Editing never drops the selector keys
 * (scope / mitreTechniques / allowedActions) and only changes what FUTURE recommendations see.
 * Real routes + JWT middleware + controller + use cases; an in-memory repository.
 */

type Audit = { tenantId: string; actor: string; action: string; entityId: string; metadata?: Record<string, unknown> };

class MemoryPlaybooks implements IPlaybookRepository {
  rows = new Map<string, Playbook>();
  executions = new Map<string, number>();
  /** Phase 1D revision state; a playbook missing here has no revisions (pre-revision behavior). */
  revisions = new Map<string, { publishedRevisionId: string | null; revisionCount: number; historyCount: number }>();
  private seq = 0;
  async revisionState(id: string, tenantId: string) {
    const p = this.rows.get(id);
    return p && p.tenantId === tenantId ? this.revisions.get(id) ?? { publishedRevisionId: null, revisionCount: 0, historyCount: 0 } : null;
  }
  async countExecutions(id: string) {
    return this.executions.get(id) ?? 0;
  }
  async delete(id: string) {
    this.rows.delete(id);
  }
  seed(p: Parameters<typeof Playbook.create>[0]) {
    this.rows.set(p.id, Playbook.create(p));
  }
  async findById(id: string, tenantId: string) {
    const p = this.rows.get(id);
    return p && p.tenantId === tenantId ? p : null;
  }
  async findByCode(code: string, tenantId: string) {
    return [...this.rows.values()].find((p) => p.code === code && p.tenantId === tenantId) ?? null;
  }
  async findAll(tenantId: string) {
    return [...this.rows.values()].filter((p) => p.tenantId === tenantId);
  }
  /** Phase 1D: a new playbook is a DRAFT row + DRAFT revision 1. */
  async createDraft(d: CreatePlaybookData) {
    const id = `pb-${++this.seq}`;
    const p = Playbook.create({
      id, tenantId: d.tenantId, code: d.code, name: d.name, description: d.description, version: d.version, status: "DRAFT",
      triggerConditions: d.incidentType ? { incidentType: d.incidentType } : {},
      steps: d.steps.map((s, i) => ({ id: `${id}-s${i}`, ...s })),
    });
    this.rows.set(id, p);
    this.revisions.set(id, { publishedRevisionId: null, revisionCount: 1, historyCount: 0 });
    return { playbook: p, revision: { id: `${id}-r1`, revisionNumber: 1, status: "DRAFT" as const, version: d.version } };
  }
  async update(id: string, _tenantId: string, d: UpdatePlaybookData) {
    const cur = this.rows.get(id)!.toJSON();
    const { incidentType, steps, ...fields } = d;
    const trigger = { ...(cur.triggerConditions ?? {}) };
    if (incidentType !== undefined) {
      if (incidentType) trigger.incidentType = incidentType;
      else delete trigger.incidentType;
    }
    const next = Playbook.create({
      ...cur,
      ...Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined)),
      triggerConditions: trigger,
      steps: steps ? steps.map((s, i) => ({ id: `${id}-n${i}`, ...s })) : cur.steps,
    } as never);
    this.rows.set(id, next);
    return next;
  }
}

const repo = new MemoryPlaybooks();
const audits: Audit[] = [];
const auditor = { record: async (a: Audit) => void audits.push(a) };
const controller = new PlaybookController(
  new CreatePlaybookUseCase(repo, auditor as never),
  new UpdatePlaybookUseCase(repo, auditor as never),
  new GetPlaybookUseCase(repo),
  new ListPlaybooksUseCase(repo),
  new DeletePlaybookUseCase(repo, auditor as never),
);

const TENANT = "tenant-A";
const SSH = {
  id: "pb-ssh", tenantId: TENANT, code: "PB-SSH-BRUTEFORCE", name: "SSH Brute Force Response", description: null, version: "1.0", status: "ACTIVE" as const,
  triggerConditions: { scope: "INCIDENT", incidentType: "SSH_BRUTE_FORCE", mitreTechniques: ["T1110"], allowedActions: ["ACT-BLOCK-SOURCE-IP"] },
  steps: [{ id: "s1", stepOrder: 1, title: "Contain the source", description: null }],
};

let server: Server;
let base = "";
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api/playbooks", buildPlaybookRoutes(controller));
  server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => {
  repo.rows.clear();
  repo.seed(SSH);
  repo.executions.clear();
  repo.revisions.clear();
  audits.length = 0;
});

const token = (role: string) => `Bearer ${signToken({ id: `u-${role}`, tenantId: TENANT, role })}`;
const call = async (method: string, path: string, body?: unknown, role?: string) => {
  const res = await fetch(`${base}/api/playbooks${path}`, {
    method,
    headers: { "content-type": "application/json", ...(role ? { authorization: token(role) } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> };
};
const NEW = { code: "PB-TEST-DEMO", name: "Test Playbook", description: "Created in a test", incidentType: "TEST_CASE", steps: [{ stepOrder: 1, title: "Confirm the scope" }, { stepOrder: 2, title: "Contain" }] };

describe("Playbook management — authorization (SOC, IR_TEAM, admin manage; others read)", () => {
  it.each(["SOC", "IR_TEAM"])("%s can create and edit; the audit names that user", async (role) => {
    const created = await call("POST", "/", { ...NEW, code: `PB-${role.replace("_", "-")}` }, role);
    expect(created.status).toBe(201);
    expect((await call("PUT", "/pb-ssh", { description: `edited by ${role}` }, role)).status).toBe(200);
    expect(audits.map((a) => [a.action, a.actor])).toEqual([["CREATE_PLAYBOOK", `u-${role}`], ["UPDATE_PLAYBOOK", `u-${role}`]]);
  });
  it.each(["MANAGER", "VIEWER"])("%s cannot create or edit -> 403, nothing changes", async (role) => {
    expect((await call("POST", "/", NEW, role)).status).toBe(403);
    expect((await call("PUT", "/pb-ssh", { name: "x" }, role)).status).toBe(403);
    expect(repo.rows.size).toBe(1);
    expect(repo.rows.get("pb-ssh")!.name).toBe("SSH Brute Force Response");
    expect(audits).toEqual([]);
  });
  it("without a token -> 401", async () => {
    expect((await call("POST", "/", NEW)).status).toBe(401);
    expect((await call("PUT", "/pb-ssh", { name: "x" })).status).toBe(401);
  });
});

describe("Playbook management — create", () => {
  it("admin creates a DRAFT playbook (revision 1 DRAFT) with incident type and steps; CREATE_PLAYBOOK audited with the actor", async () => {
    const r = await call("POST", "/", NEW, "admin");
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ code: "PB-TEST-DEMO", name: "Test Playbook", status: "DRAFT", triggerConditions: { incidentType: "TEST_CASE" }, revision: { revisionNumber: 1, status: "DRAFT" } });
    expect((r.body.steps as { title: string }[]).map((s) => s.title)).toEqual(["Confirm the scope", "Contain"]);
    expect(audits).toEqual([expect.objectContaining({ action: "CREATE_PLAYBOOK", actor: "u-admin", tenantId: TENANT, entityId: r.body.id })]);
  });
  it("duplicate code -> 409 DUPLICATE_CODE, no audit", async () => {
    const r = await call("POST", "/", { ...NEW, code: "PB-SSH-BRUTEFORCE" }, "admin");
    expect(r).toMatchObject({ status: 409, body: { error: "DUPLICATE_CODE" } });
    expect(audits).toEqual([]);
  });
  it.each([
    ["empty name", { ...NEW, name: "   " }],
    ["no steps", { ...NEW, steps: [] }],
    ["blank step title", { ...NEW, steps: [{ stepOrder: 1, title: " " }] }],
    ["duplicate step order", { ...NEW, steps: [{ stepOrder: 1, title: "a" }, { stepOrder: 1, title: "b" }] }],
    ["bad incident type", { ...NEW, incidentType: "ssh brute force" }],
    ["unknown field", { ...NEW, objective: "not a Playbook field" }],
  ])("%s -> 400 VALIDATION_ERROR, nothing created", async (_label, body) => {
    const r = await call("POST", "/", body, "admin");
    expect(r).toMatchObject({ status: 400, body: { error: "VALIDATION_ERROR" } });
    expect(repo.rows.size).toBe(1);
  });
});

describe("Playbook management — edit / activate / deactivate", () => {
  it("edit name, incident type and steps keeps scope / MITRE / allowed actions; UPDATE_PLAYBOOK audited", async () => {
    const r = await call("PUT", "/pb-ssh", { name: "SSH Brute Force Response v2", incidentType: "SSH_BRUTE_FORCE", steps: [{ stepOrder: 1, title: "Block the source" }, { stepOrder: 2, title: "Reset credentials" }] }, "admin");
    expect(r.status).toBe(200);
    expect(r.body.triggerConditions).toEqual(SSH.triggerConditions);
    expect((r.body.steps as { title: string }[]).map((s) => s.title)).toEqual(["Block the source", "Reset credentials"]);
    expect(audits).toEqual([expect.objectContaining({ action: "UPDATE_PLAYBOOK", actor: "u-admin", entityId: "pb-ssh", metadata: expect.objectContaining({ fields: ["name", "incidentType", "steps"] }) })]);
  });
  it("editing does not change which playbook the recommendation selector picks (it reads the stored keys)", async () => {
    await call("PUT", "/pb-ssh", { description: "clarified" }, "admin");
    expect(new PlaybookSelector().select([repo.rows.get("pb-ssh")!], ["T1110"])?.code).toBe("PB-SSH-BRUTEFORCE");
  });
  it("deactivate -> DEPRECATED (not selectable for future recommendations), DEACTIVATE_PLAYBOOK; activate -> ACTIVATE_PLAYBOOK", async () => {
    const off = await call("PUT", "/pb-ssh", { status: "DEPRECATED" }, "admin");
    expect(off.body.status).toBe("DEPRECATED");
    expect(new PlaybookSelector().select([repo.rows.get("pb-ssh")!], ["T1110"])).toBeNull();
    const on = await call("PUT", "/pb-ssh", { status: "ACTIVE" }, "admin");
    expect(on.body.status).toBe("ACTIVE");
    expect(audits.map((a) => a.action)).toEqual(["DEACTIVATE_PLAYBOOK", "ACTIVATE_PLAYBOOK"]);
  });
  it("setting the same status again is not audited as a change", async () => {
    await call("PUT", "/pb-ssh", { status: "ACTIVE" }, "admin");
    expect(audits).toEqual([]);
  });
  it.each([
    ["empty name", { name: "" }],
    ["empty steps", { steps: [] }],
  ])("%s -> 400, playbook unchanged", async (_label, body) => {
    expect((await call("PUT", "/pb-ssh", body, "admin")).status).toBe(400);
    expect(repo.rows.get("pb-ssh")!.toJSON()).toMatchObject({ name: SSH.name, steps: SSH.steps });
  });
  it("unknown playbook -> 404", async () => {
    expect((await call("PUT", "/nope", { name: "x" }, "admin")).status).toBe(404);
  });
  it("a newly created (DRAFT, revision-managed) playbook -> 409 PLAYBOOK_REVISION_MANAGED, unchanged", async () => {
    const created = await call("POST", "/", NEW, "admin");
    audits.length = 0;
    expect(await call("PUT", `/${created.body.id}`, { status: "ACTIVE" }, "admin")).toMatchObject({ status: 409, body: { error: "PLAYBOOK_REVISION_MANAGED" } });
    expect(repo.rows.get(created.body.id as string)!.status).toBe("DRAFT");
    expect(audits).toEqual([]);
  });
  it("published playbook -> 409 PLAYBOOK_PUBLISHED_IMMUTABLE, unchanged, no audit", async () => {
    repo.revisions.set("pb-ssh", { publishedRevisionId: "rev-1", revisionCount: 1, historyCount: 1 });
    const before = repo.rows.get("pb-ssh")!.toJSON();
    for (const body of [{ name: "Renamed" }, { status: "DEPRECATED" }, { steps: [{ stepOrder: 1, title: "x" }] }]) {
      expect(await call("PUT", "/pb-ssh", body, "admin")).toMatchObject({ status: 409, body: { error: "PLAYBOOK_PUBLISHED_IMMUTABLE" } });
    }
    expect(repo.rows.get("pb-ssh")!.toJSON()).toEqual(before);
    expect(audits).toEqual([]);
  });
});

describe("Playbook management — delete (x)", () => {
  it.each(["SOC", "IR_TEAM", "admin"])("%s deletes with a reason; DELETE_PLAYBOOK audited with actor, reason and a copy", async (role) => {
    const r = await call("DELETE", "/pb-ssh", { reason: "Replaced by a newer playbook" }, role);
    expect(r).toEqual({ status: 200, body: { deleted: true, id: "pb-ssh", code: "PB-SSH-BRUTEFORCE" } });
    expect(repo.rows.has("pb-ssh")).toBe(false);
    expect(audits).toEqual([
      expect.objectContaining({
        action: "DELETE_PLAYBOOK",
        actor: `u-${role}`,
        entityId: "pb-ssh",
        metadata: expect.objectContaining({ code: "PB-SSH-BRUTEFORCE", reason: "Replaced by a newer playbook", snapshot: expect.objectContaining({ steps: expect.any(Array), triggerConditions: SSH.triggerConditions }) }),
      }),
    ]);
  });
  it("no reason is needed: deleted, audited with reason null and the actor", async () => {
    expect((await call("DELETE", "/pb-ssh", {}, "SOC")).status).toBe(200);
    expect(repo.rows.has("pb-ssh")).toBe(false);
    expect(audits).toEqual([expect.objectContaining({ action: "DELETE_PLAYBOOK", actor: "u-SOC", metadata: expect.objectContaining({ reason: null, snapshot: expect.any(Object) }) })]);
  });
  it.each(["MANAGER", "VIEWER"])("%s -> 403, nothing deleted", async (role) => {
    expect((await call("DELETE", "/pb-ssh", { reason: "x" }, role)).status).toBe(403);
    expect(repo.rows.has("pb-ssh")).toBe(true);
  });
  it("a playbook referenced by an execution cannot be deleted -> 409 PLAYBOOK_IN_USE, no audit", async () => {
    repo.executions.set("pb-ssh", 1);
    expect(await call("DELETE", "/pb-ssh", { reason: "x" }, "SOC")).toMatchObject({ status: 409, body: { error: "PLAYBOOK_IN_USE" } });
    expect(repo.rows.has("pb-ssh")).toBe(true);
    expect(audits).toEqual([]);
  });
  it("unknown playbook -> 404", async () => {
    expect((await call("DELETE", "/nope", { reason: "x" }, "SOC")).status).toBe(404);
  });
  it("a published playbook (revision history) -> 409 PLAYBOOK_REVISION_HISTORY_EXISTS, not deleted, no audit", async () => {
    repo.revisions.set("pb-ssh", { publishedRevisionId: "rev-1", revisionCount: 1, historyCount: 1 });
    expect(await call("DELETE", "/pb-ssh", { reason: "x" }, "admin")).toMatchObject({ status: 409, body: { error: "PLAYBOOK_REVISION_HISTORY_EXISTS" } });
    expect(repo.rows.has("pb-ssh")).toBe(true);
    expect(audits).toEqual([]);
  });
});
