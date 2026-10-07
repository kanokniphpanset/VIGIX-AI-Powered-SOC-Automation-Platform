import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { PrismaClient } from "@prisma/client";
import { randomUUID } from "crypto";
import { signServiceToken, signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildPlaybookRoutes } from "../src/presentation/http/routes/playbook.routes";
import { PlaybookController } from "../src/presentation/http/controllers/PlaybookController";
import { PlaybookRevisionController } from "../src/presentation/http/controllers/PlaybookRevisionController";
import { AtomicWorkflow } from "../src/infrastructure/database/postgres/AtomicWorkflow";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaPlaybookRevisionRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRevisionRepository.prisma";
import { CreatePlaybookUseCase } from "../src/application/playbook/use-cases/CreatePlaybook.usecase";
import { UpdatePlaybookUseCase } from "../src/application/playbook/use-cases/UpdatePlaybook.usecase";
import { GetPlaybookUseCase } from "../src/application/playbook/use-cases/GetPlaybook.usecase";
import { ListPlaybooksUseCase } from "../src/application/playbook/use-cases/ListPlaybooks.usecase";
import { DeletePlaybookUseCase } from "../src/application/playbook/use-cases/DeletePlaybook.usecase";
import { ListPlaybookRevisionsUseCase } from "../src/application/playbook/use-cases/ListPlaybookRevisions.usecase";
import { CreatePlaybookRevisionUseCase, nextVersion } from "../src/application/playbook/use-cases/CreatePlaybookRevision.usecase";
import { UpdatePlaybookDraftUseCase } from "../src/application/playbook/use-cases/UpdatePlaybookDraft.usecase";
import { PublishPlaybookRevisionUseCase } from "../src/application/playbook/use-cases/PublishPlaybookRevision.usecase";
import { RollbackPlaybookRevisionUseCase } from "../src/application/playbook/use-cases/RollbackPlaybookRevision.usecase";
import { PlaybookSelector } from "../src/application/recommendation/services/PlaybookSelector";
import { PLAYBOOK_SEED_ACTOR, playbookSeedDefinitions, seedPlaybookDefinitions, seedPlaybooks } from "../prisma/seeds/playbook.seed";

/**
 * Phase 1D STEP 6 — simplified playbook lifecycle over the real HTTP routes: SOC / IR_TEAM create a DRAFT, edit it,
 * publish it directly (no review / approval), create a new version from the published one, publish it and roll back.
 * Published content is immutable and revision history is never deleted. Seed keeps its STEP 5 behavior.
 * Dedicated Phase 1D databases only; tenants named "Phase1D tenant …". The fresh-database part needs
 * PHASE1D_FRESH_TEST_DATABASE_URL (an empty, migrated vigix_phase1d_test_fresh*).
 */
const url = process.env.PHASE1D_TEST_DATABASE_URL;
const freshUrl = process.env.PHASE1D_FRESH_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
const freshSuite = freshUrl ? describe : describe.skip;
const guard = (u: string | undefined, pattern: RegExp) => {
  if (!u || !pattern.test(new URL(u).pathname.slice(1))) throw new Error("Dedicated Phase 1D database required; runtime/evaluation targets are forbidden");
};

jest.setTimeout(60000);

/** The controllers exactly as container.ts wires them, on the given client. */
function buildApp(db: PrismaClient) {
  const atomic = new AtomicWorkflow(db);
  const repo = new PrismaPlaybookRepository(atomic.prisma);
  const revisions = new PrismaPlaybookRevisionRepository(atomic.prisma);
  const audit = new AuditLogger(atomic.prisma);
  const controller = new PlaybookController(
    atomic.wrap(new CreatePlaybookUseCase(repo, audit), "playbook"),
    atomic.wrap(new UpdatePlaybookUseCase(repo, audit), "playbook"),
    new GetPlaybookUseCase(repo),
    new ListPlaybooksUseCase(repo),
    atomic.wrap(new DeletePlaybookUseCase(repo, audit), "playbook"),
  );
  const revisionController = new PlaybookRevisionController(
    new ListPlaybookRevisionsUseCase(repo, revisions),
    atomic.wrap(new CreatePlaybookRevisionUseCase(revisions, audit), "playbook"),
    atomic.wrap(new UpdatePlaybookDraftUseCase(revisions, audit), "playbook"),
    atomic.wrap(new PublishPlaybookRevisionUseCase(revisions, audit), "playbook"),
    atomic.wrap(new RollbackPlaybookRevisionUseCase(revisions, audit), "playbook"),
  );
  const app = express();
  app.use(express.json());
  app.use("/api/playbooks", buildPlaybookRoutes(controller, revisionController));
  return { app, atomic, repo, audit };
}

async function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  const server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  return { server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

function client(base: string) {
  return async (method: string, path: string, body: unknown, tenantId: string, role = "SOC", authorization?: string) => {
    const res = await fetch(`${base}/api/playbooks${path}`, {
      method,
      headers: { "content-type": "application/json", authorization: authorization ?? `Bearer ${signToken({ id: `u-${role}`, tenantId, role })}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, any> };
  };
}

suite("Phase 1D — simplified playbook lifecycle (create / edit / publish / new version / rollback / delete)", () => {
  let db: PrismaClient;
  let server: Server;
  let call: ReturnType<typeof client>;
  let built: ReturnType<typeof buildApp>;
  let tenantA: string;
  let tenantB: string;

  const NEW = (code = `PB-T1D6-${randomUUID().slice(0, 8).toUpperCase()}`) => ({
    code, name: "Lifecycle playbook", description: "Created in a test", incidentType: "TEST_CASE",
    steps: [{ stepOrder: 2, title: "Contain" }, { stepOrder: 1, title: "Confirm the scope", description: "first" }],
  });
  async function snapshot(playbookId: string, tenantId: string) {
    return {
      playbook: await db.playbook.findUnique({ where: { id: playbookId } }),
      steps: await db.playbookStep.findMany({ where: { playbookId }, orderBy: { stepOrder: "asc" } }),
      revisions: await db.playbookRevision.findMany({ where: { playbookId }, orderBy: { revisionNumber: "asc" } }),
      audit: await db.auditLog.findMany({ where: { tenantId }, orderBy: [{ createdAt: "asc" }, { id: "asc" }] }),
    };
  }
  const runtimeSteps = (steps: { stepOrder: number; title: string; description: string | null }[]) => steps.map((x) => ({ stepOrder: x.stepOrder, title: x.title, description: x.description }));
  /** Created by SOC (DRAFT) and published by SOC: v1.0 live. */
  async function publishedPlaybook(tenantId = tenantA) {
    const created = await call("POST", "/", NEW(), tenantId, "SOC");
    const published = await call("POST", `/${created.body.id}/revisions/${created.body.revision.id}/publish`, {}, tenantId, "SOC");
    expect(published.status).toBe(200);
    return { id: created.body.id as string, rev1: created.body.revision.id as string, code: created.body.code as string };
  }
  const auditActions = (s: Awaited<ReturnType<typeof snapshot>>, ids: string[]) => s.audit.filter((a) => ids.includes(a.entityId)).map((a) => a.action);

  beforeAll(async () => {
    guard(url, /^vigix_phase1d_test_[a-z0-9_]+$/);
    db = new PrismaClient({ datasources: { db: { url } } });
    tenantA = (await db.tenant.create({ data: { name: "Phase1D tenant lifecycle A" } })).id;
    tenantB = (await db.tenant.create({ data: { name: "Phase1D tenant lifecycle B" } })).id;
    built = buildApp(db);
    const l = await listen(built.app);
    server = l.server;
    call = client(l.base);
  });
  afterAll(async () => {
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    await db?.$disconnect();
  });

  describe("create", () => {
    test.each(["SOC", "IR_TEAM"])("%s creates a DRAFT playbook + revision 1 DRAFT (no published revision), content = definition", async (role) => {
      const body = NEW();
      const r = await call("POST", "/", body, tenantA, role);
      expect(r.status).toBe(201);
      expect(r.body).toMatchObject({ code: body.code, status: "DRAFT", version: "1.0", revision: { revisionNumber: 1, status: "DRAFT", version: "1.0" } });
      const s = await snapshot(r.body.id, tenantA);
      expect(s.playbook).toMatchObject({ status: "DRAFT", publishedRevisionId: null, triggerConditions: { incidentType: "TEST_CASE" } });
      expect(s.revisions).toEqual([expect.objectContaining({ revisionNumber: 1, status: "DRAFT", createdBy: `u-${role}`, publishedAt: null })]);
      expect(s.revisions[0].content).toEqual({
        code: body.code, name: body.name, description: body.description, triggerConditions: { incidentType: "TEST_CASE" }, n8nWorkflowId: null,
        playbookStatus: "ACTIVE", version: "1.0",
        steps: [{ stepOrder: 1, title: "Confirm the scope", description: "first" }, { stepOrder: 2, title: "Contain", description: null }],
      });
      expect(auditActions(s, [r.body.id])).toEqual(["CREATE_PLAYBOOK"]);
    });

    test("VIEWER → 403 and a service token → rejected; nothing created", async () => {
      const body = NEW();
      expect((await call("POST", "/", body, tenantA, "VIEWER")).status).toBe(403);
      const service = `Bearer ${signServiceToken({ id: "service:ai-orchestrator", tenantId: tenantA, scopes: ["orchestrator:callback"], jobIds: [] })}`;
      expect([401, 403]).toContain((await call("POST", "/", body, tenantA, "SOC", service)).status);
      expect(await db.playbook.findUnique({ where: { code: body.code } })).toBeNull();
    });

    test("the DRAFT row is never selectable, even with INCIDENT scope and matching techniques", async () => {
      const r = await call("POST", "/", NEW(), tenantA);
      await db.playbook.update({ where: { id: r.body.id }, data: { triggerConditions: { scope: "INCIDENT", incidentType: "TEST_CASE", mitreTechniques: ["T1110"] } } });
      const all = await new PrismaPlaybookRepository(db).findAll(tenantA);
      expect(new PlaybookSelector().select(all.filter((p) => p.id === r.body.id), ["T1110"])).toBeNull();
    });

    test("playbook + revision are atomic: a failing revision insert leaves nothing", async () => {
      class FailingRevision extends PrismaPlaybookRepository {
        protected async createInitialRevision(): Promise<never> { throw new Error("revision insert failed"); }
      }
      const create = built.atomic.wrap(new CreatePlaybookUseCase(new FailingRevision(built.atomic.prisma), built.audit), "playbook");
      const body = NEW();
      await expect(create.execute({ ...body, version: "1.0", status: "ACTIVE", tenantId: tenantA, actor: "u-SOC" })).rejects.toThrow("revision insert failed");
      expect(await db.playbook.findUnique({ where: { code: body.code } })).toBeNull();
    });

    test("duplicate code → 409 DUPLICATE_CODE", async () => {
      const body = NEW();
      await call("POST", "/", body, tenantA);
      expect(await call("POST", "/", body, tenantA)).toMatchObject({ status: 409, body: { error: "DUPLICATE_CODE" } });
      expect(await db.playbook.count({ where: { code: body.code } })).toBe(1);
    });
  });

  describe("edit draft", () => {
    test.each(["SOC", "IR_TEAM"])("%s edits a never-published draft: revision content updated, DRAFT row mirrors it, still not live", async (role) => {
      const r = await call("POST", "/", NEW(), tenantA, "SOC");
      const edit = await call("PUT", `/${r.body.id}/revisions/${r.body.revision.id}`, { name: "Edited", incidentType: "OTHER_CASE", steps: [{ stepOrder: 1, title: "Only step" }] }, tenantA, role);
      expect(edit.status).toBe(200);
      const s = await snapshot(r.body.id, tenantA);
      expect(s.revisions).toHaveLength(1);
      expect(s.revisions[0]).toMatchObject({ status: "DRAFT", content: expect.objectContaining({ name: "Edited", triggerConditions: { incidentType: "OTHER_CASE" }, steps: [{ stepOrder: 1, title: "Only step", description: null }] }) });
      expect(s.playbook).toMatchObject({ status: "DRAFT", publishedRevisionId: null, name: "Edited", triggerConditions: { incidentType: "OTHER_CASE" } });
      expect(runtimeSteps(s.steps)).toEqual([{ stepOrder: 1, title: "Only step", description: null }]);
      expect(s.audit.filter((a) => a.entityId === r.body.revision.id)).toEqual([expect.objectContaining({ action: "PLAYBOOK_REVISION_UPDATED", actor: `u-${role}` })]);
    });

    test("PUT /:id on a draft playbook stays 409 PLAYBOOK_REVISION_MANAGED; a published revision cannot be edited", async () => {
      const draft = await call("POST", "/", NEW(), tenantA);
      expect((await call("PUT", `/${draft.body.id}`, { name: "x" }, tenantA)).body).toEqual({ error: "PLAYBOOK_REVISION_MANAGED" });
      const p = await publishedPlaybook();
      const before = await snapshot(p.id, tenantA);
      expect(await call("PUT", `/${p.id}/revisions/${p.rev1}`, { name: "x" }, tenantA)).toMatchObject({ status: 409, body: { error: "INVALID_REVISION_TRANSITION" } });
      expect((await call("PUT", `/${p.id}`, { name: "x" }, tenantA)).body).toEqual({ error: "PLAYBOOK_PUBLISHED_IMMUTABLE" });
      expect(await snapshot(p.id, tenantA)).toEqual(before);
    });
  });

  describe("publish", () => {
    test("SOC publishes a draft directly (first publish): live ACTIVE, projection = content, audited", async () => {
      const r = await call("POST", "/", NEW(), tenantA, "IR_TEAM");
      const pub = await call("POST", `/${r.body.id}/revisions/${r.body.revision.id}/publish`, { reason: "go live" }, tenantA, "SOC");
      expect(pub).toMatchObject({ status: 200, body: { revisionId: r.body.revision.id, version: "1.0" } });
      const s = await snapshot(r.body.id, tenantA);
      const content = s.revisions[0].content as any;
      expect(s.revisions[0]).toMatchObject({ status: "PUBLISHED", publishedBy: "u-SOC", createdBy: "u-IR_TEAM" });
      expect(s.playbook).toMatchObject({ publishedRevisionId: r.body.revision.id, status: "ACTIVE", name: content.name, triggerConditions: content.triggerConditions, version: "1.0" });
      expect(runtimeSteps(s.steps)).toEqual(content.steps);
      expect(auditActions(s, [r.body.id, r.body.revision.id])).toEqual(["CREATE_PLAYBOOK", "PLAYBOOK_REVISION_PUBLISHED"]);
    });

    test("admin, VIEWER and service tokens cannot publish; nothing changes", async () => {
      const r = await call("POST", "/", NEW(), tenantA);
      const before = await snapshot(r.body.id, tenantA);
      const path = `/${r.body.id}/revisions/${r.body.revision.id}/publish`;
      expect((await call("POST", path, {}, tenantA, "admin")).status).toBe(403);
      expect((await call("POST", path, {}, tenantA, "VIEWER")).status).toBe(403);
      const service = `Bearer ${signServiceToken({ id: "service:ai-orchestrator", tenantId: tenantA, scopes: ["orchestrator:callback"], jobIds: [] })}`;
      expect([401, 403]).toContain((await call("POST", path, {}, tenantA, "SOC", service)).status);
      expect(await snapshot(r.body.id, tenantA)).toEqual(before);
    });

    test("negative: already published, wrong tenant, wrong playbook, invalid content → semantic errors, nothing changes", async () => {
      const p = await publishedPlaybook();
      const other = await call("POST", "/", NEW(), tenantA);
      const before = await snapshot(p.id, tenantA);
      expect(await call("POST", `/${p.id}/revisions/${p.rev1}/publish`, {}, tenantA)).toMatchObject({ status: 409, body: { error: "INVALID_REVISION_TRANSITION" } });
      expect(await call("POST", `/${p.id}/revisions/${p.rev1}/publish`, {}, tenantB)).toMatchObject({ status: 404, body: { error: "PLAYBOOK_NOT_FOUND" } });
      expect(await call("POST", `/${p.id}/revisions/${other.body.revision.id}/publish`, {}, tenantA)).toMatchObject({ status: 404, body: { error: "PLAYBOOK_REVISION_NOT_FOUND" } });
      expect(await snapshot(p.id, tenantA)).toEqual(before);

      const bad = await call("POST", "/", NEW(), tenantA);
      const stored = await db.playbookRevision.findUniqueOrThrow({ where: { id: bad.body.revision.id } });
      await db.playbookRevision.update({ where: { id: bad.body.revision.id }, data: { content: { ...(stored.content as object), steps: [] } } });
      const badBefore = await snapshot(bad.body.id, tenantA);
      expect(await call("POST", `/${bad.body.id}/revisions/${bad.body.revision.id}/publish`, {}, tenantA)).toMatchObject({ status: 422, body: { error: "PLAYBOOK_REVISION_INVALID" } });
      expect(await snapshot(bad.body.id, tenantA)).toEqual(badBefore);
    });
  });

  describe("create new version → publish → rollback", () => {
    test("new version copies the published revision into DRAFT v1.1; nothing live changes; editing it leaves the live playbook alone", async () => {
      const p = await publishedPlaybook();
      const before = await snapshot(p.id, tenantA);
      const created = await call("POST", `/${p.id}/revisions`, { reason: "update steps" }, tenantA, "IR_TEAM");
      expect(created).toMatchObject({ status: 201, body: { revisionNumber: 2, version: "1.1", status: "DRAFT", createdBy: "u-IR_TEAM" } });

      const after = await snapshot(p.id, tenantA);
      const [v1, v2] = after.revisions;
      expect(v1).toEqual(before.revisions[0]); // published revision unchanged
      expect(after.playbook).toEqual(before.playbook); // pointer + runtime unchanged
      expect(after.steps).toEqual(before.steps);
      expect(v2.content).toEqual({ ...(v1.content as object), version: "1.1" });
      expect(auditActions(after, [v2.id])).toEqual(["PLAYBOOK_REVISION_CREATED"]);

      expect(await call("POST", `/${p.id}/revisions`, {}, tenantA)).toMatchObject({ status: 409, body: { error: "PLAYBOOK_DRAFT_EXISTS" } });
      expect((await call("POST", `/${p.id}/revisions`, {}, tenantB)).status).toBe(404);

      expect((await call("PUT", `/${p.id}/revisions/${v2.id}`, { name: "v1.1 name", steps: [{ stepOrder: 1, title: "New step" }] }, tenantA, "SOC")).status).toBe(200);
      const edited = await snapshot(p.id, tenantA);
      expect(edited.playbook).toEqual(before.playbook);
      expect(edited.steps).toEqual(before.steps);
      expect(edited.revisions[0]).toEqual(before.revisions[0]);
    });

    test("a never-published playbook has no 'new version' (edit its draft instead)", async () => {
      const r = await call("POST", "/", NEW(), tenantA);
      expect(await call("POST", `/${r.body.id}/revisions`, {}, tenantA)).toMatchObject({ status: 409, body: { error: "INVALID_REVISION_TRANSITION" } });
    });

    test("concurrent 'create new version' requests: one draft only", async () => {
      const p = await publishedPlaybook();
      const results = await Promise.all([call("POST", `/${p.id}/revisions`, {}, tenantA), call("POST", `/${p.id}/revisions`, {}, tenantA, "IR_TEAM")]);
      expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
      expect(await db.playbookRevision.count({ where: { playbookId: p.id, status: "DRAFT" } })).toBe(1);
    });

    test("publishing v1.1 supersedes v1.0; rollback by SOC re-publishes v1.0 unchanged; history preserved", async () => {
      const p = await publishedPlaybook();
      const v2 = (await call("POST", `/${p.id}/revisions`, {}, tenantA)).body.id as string;
      await call("PUT", `/${p.id}/revisions/${v2}`, { name: "Second version", steps: [{ stepOrder: 1, title: "v2 step" }] }, tenantA);
      expect((await call("POST", `/${p.id}/revisions/${v2}/publish`, {}, tenantA, "IR_TEAM")).status).toBe(200);

      let s = await snapshot(p.id, tenantA);
      expect(s.revisions.map((r) => r.status)).toEqual(["SUPERSEDED", "PUBLISHED"]);
      expect(s.playbook).toMatchObject({ publishedRevisionId: v2, name: "Second version", version: "1.1", status: "ACTIVE" });
      expect(runtimeSteps(s.steps)).toEqual([{ stepOrder: 1, title: "v2 step", description: null }]);
      const v1Content = s.revisions[0].content;

      expect((await call("POST", `/${p.id}/revisions/${p.rev1}/rollback`, {}, tenantA, "admin")).status).toBe(403);
      const rb = await call("POST", `/${p.id}/revisions/${p.rev1}/rollback`, { reason: "bad steps" }, tenantA, "SOC");
      expect(rb).toMatchObject({ status: 200, body: { revisionId: p.rev1, version: "1.0" } });
      s = await snapshot(p.id, tenantA);
      expect(s.revisions.map((r) => r.status)).toEqual(["PUBLISHED", "SUPERSEDED"]);
      expect(s.revisions[0].content).toEqual(v1Content);
      expect(s.playbook).toMatchObject({ publishedRevisionId: p.rev1, version: "1.0", name: (v1Content as any).name });
      expect(runtimeSteps(s.steps)).toEqual((v1Content as any).steps);
      const rolled = s.audit.find((a) => a.action === "PLAYBOOK_REVISION_ROLLED_BACK" && a.entityId === p.rev1)!;
      expect(rolled).toMatchObject({ actor: "u-SOC", metadata: expect.objectContaining({ previousRevisionId: v2, before: expect.objectContaining({ status: "SUPERSEDED" }), after: expect.objectContaining({ status: "PUBLISHED", publishedBy: "u-SOC" }) }) });

      // The whole history is listed to any authenticated role.
      const list = await call("GET", `/${p.id}/revisions`, undefined, tenantA, "VIEWER");
      expect(list.body.items.map((r: any) => [r.version, r.status])).toEqual([["1.0", "PUBLISHED"], ["1.1", "SUPERSEDED"]]);
    });
  });

  describe("delete", () => {
    test("a never-published (draft-only) playbook is deleted with its draft; audited", async () => {
      const r = await call("POST", "/", NEW(), tenantA);
      expect(await call("DELETE", `/${r.body.id}`, {}, tenantA)).toMatchObject({ status: 200, body: { deleted: true } });
      expect(await db.playbook.findUnique({ where: { id: r.body.id } })).toBeNull();
      expect(await db.playbookRevision.count({ where: { playbookId: r.body.id } })).toBe(0);
      expect(await db.auditLog.findMany({ where: { tenantId: tenantA, entityId: r.body.id, action: "DELETE_PLAYBOOK" } })).toHaveLength(1);
    });

    test("a published playbook (with an open draft too) → 409, nothing deleted", async () => {
      const p = await publishedPlaybook();
      await call("POST", `/${p.id}/revisions`, {}, tenantA);
      const before = await snapshot(p.id, tenantA);
      expect(await call("DELETE", `/${p.id}`, {}, tenantA)).toMatchObject({ status: 409, body: { error: "PLAYBOOK_REVISION_HISTORY_EXISTS" } });
      expect(await snapshot(p.id, tenantA)).toEqual(before);
    });
  });

  test("version convention: 1.0 → 1.1, skips used versions, non-numeric gets .1", () => {
    expect(nextVersion("1.0", ["1.0"])).toBe("1.1");
    expect(nextVersion("1.9", ["1.9", "1.10"])).toBe("1.11");
    expect(nextVersion("2024a", [])).toBe("2024a.1");
  });

  describe("seed on a database that already has published playbooks (copy of production)", () => {
    const existingTenant = async () => (await db.playbook.findUniqueOrThrow({ where: { code: "STC-001" }, select: { tenantId: true } })).tenantId;
    const seededState = async () => {
      const playbooks = await db.playbook.findMany({ where: { code: { in: playbookSeedDefinitions().map((d) => d.code) } }, orderBy: { code: "asc" } });
      const ids = playbooks.map((p) => p.id);
      return {
        playbooks,
        steps: await db.playbookStep.findMany({ where: { playbookId: { in: ids } }, orderBy: [{ playbookId: "asc" }, { stepOrder: "asc" }] }),
        revisions: await db.playbookRevision.findMany({ where: { playbookId: { in: ids } }, orderBy: [{ playbookId: "asc" }, { revisionNumber: "asc" }] }),
        // Audit of the owning tenant (other suites write their own tenants' audit in parallel).
        audit: await db.auditLog.findMany({ where: { tenantId: { in: [...new Set(playbooks.map((p) => p.tenantId))] } }, orderBy: [{ createdAt: "asc" }, { id: "asc" }] }),
      };
    };

    test("existing published playbooks are PRESERVED (never overwritten, never auto-published); repeat runs too", async () => {
      const tenantId = await existingTenant();
      const before = await seededState();
      expect(before.playbooks).toHaveLength(playbookSeedDefinitions().length);
      for (let run = 0; run < 2; run++) {
        expect((await seedPlaybooks(db, tenantId)).every((o) => o.outcome === "PRESERVED_PUBLISHED")).toBe(true);
        expect(await seededState()).toEqual(before);
      }
    });

    test("seeding another tenant never touches them (SKIPPED_OTHER_TENANT)", async () => {
      const before = await seededState();
      expect((await seedPlaybooks(db, tenantA)).every((o) => o.outcome === "SKIPPED_OTHER_TENANT")).toBe(true);
      expect(await seededState()).toEqual(before);
    });

    test("new definitions become DRAFT + revision 1 DRAFT; a repeated seed preserves the draft (no duplicates)", async () => {
      const code = `PB-T1D6-SEED-${randomUUID().slice(0, 8).toUpperCase()}`;
      const defs = [{ code, name: "Seeded", description: "seeded", triggerConditions: { scope: "INCIDENT", incidentType: "SEED_CASE" }, steps: [{ stepOrder: 1, title: "one", description: "d" }] }];
      expect(await seedPlaybookDefinitions(db, tenantA, defs)).toEqual([{ code, outcome: "CREATED_DRAFT" }]);
      const playbook = await db.playbook.findUniqueOrThrow({ where: { code }, include: { revisions: true } });
      expect(playbook).toMatchObject({ status: "DRAFT", publishedRevisionId: null });
      expect(playbook.revisions).toEqual([expect.objectContaining({ revisionNumber: 1, status: "DRAFT", createdBy: PLAYBOOK_SEED_ACTOR })]);
      const before = await snapshot(playbook.id, tenantA);
      for (let run = 0; run < 2; run++) expect(await seedPlaybookDefinitions(db, tenantA, defs)).toEqual([{ code, outcome: "PRESERVED_DRAFT" }]);
      expect(await snapshot(playbook.id, tenantA)).toEqual(before);
    });

    test("a pre-revision row (no revisions) is SKIPPED, not overwritten", async () => {
      const code = `PB-T1D6-LEGACY-${randomUUID().slice(0, 8).toUpperCase()}`;
      const legacy = await db.playbook.create({ data: { tenantId: tenantA, code, name: "Legacy", triggerConditions: {}, steps: { create: [{ stepOrder: 1, title: "old" }] } } });
      const before = await snapshot(legacy.id, tenantA);
      expect(await seedPlaybookDefinitions(db, tenantA, [{ code, name: "New", description: "new", triggerConditions: {}, steps: [{ stepOrder: 1, title: "new", description: "new" }] }]))
        .toEqual([{ code, outcome: "SKIPPED_NO_REVISION" }]);
      expect(await snapshot(legacy.id, tenantA)).toEqual(before);
    });
  });
});

freshSuite("Phase 1D — seed on a fresh database + direct publish", () => {
  let db: PrismaClient;
  let tenantId: string;
  let server: Server;
  let call: ReturnType<typeof client>;

  beforeAll(async () => {
    guard(freshUrl, /^vigix_phase1d_test_fresh[a-z0-9_]*$/);
    db = new PrismaClient({ datasources: { db: { url: freshUrl } } });
    tenantId = (await db.tenant.findFirst({ where: { name: "Phase1D tenant fresh" } }))?.id ?? (await db.tenant.create({ data: { name: "Phase1D tenant fresh" } })).id;
    const l = await listen(buildApp(db).app);
    server = l.server;
    call = client(l.base);
  });
  afterAll(async () => {
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    await db?.$disconnect();
  });

  test("fresh seed creates only DRAFT playbooks + DRAFT revision 1 (nothing selectable); a second run creates nothing", async () => {
    const first = await seedPlaybooks(db, tenantId);
    const counts = async () => ({ playbooks: await db.playbook.count(), steps: await db.playbookStep.count(), revisions: await db.playbookRevision.count() });
    const afterFirst = await counts();
    const second = await seedPlaybooks(db, tenantId);
    expect(second.map((o) => o.outcome)).toEqual(first.map((o) => (o.outcome === "CREATED_DRAFT" ? "PRESERVED_DRAFT" : o.outcome)));
    expect(await counts()).toEqual(afterFirst);
    for (const def of playbookSeedDefinitions()) {
      const p = await db.playbook.findUniqueOrThrow({ where: { code: def.code }, include: { revisions: true } });
      if (p.publishedRevisionId) continue; // published by an earlier run of the test below
      expect(p).toMatchObject({ tenantId, status: "DRAFT" });
      expect(p.revisions).toEqual([expect.objectContaining({ revisionNumber: 1, status: "DRAFT", createdBy: PLAYBOOK_SEED_ACTOR })]);
      expect(p.revisions[0].content).toEqual({
        code: def.code, name: def.name, description: def.description, triggerConditions: def.triggerConditions, n8nWorkflowId: null, playbookStatus: "ACTIVE", version: "1.0",
        steps: [...def.steps].sort((a, b) => a.stepOrder - b.stepOrder),
      });
    }
  });

  test("a seeded draft goes live only when SOC publishes it; the seed then preserves it", async () => {
    const p = await db.playbook.findUniqueOrThrow({ where: { code: "PB-SSH-BRUTEFORCE" }, include: { revisions: true } });
    const selector = new PlaybookSelector();
    if (!p.publishedRevisionId) {
      expect(selector.select(await new PrismaPlaybookRepository(db).findAll(tenantId), ["T1110"])).toBeNull();
      expect((await call("POST", `/${p.id}/revisions/${p.revisions[0].id}/publish`, {}, tenantId, "SOC")).status).toBe(200);
    }
    expect(selector.select(await new PrismaPlaybookRepository(db).findAll(tenantId), ["T1110"])?.code).toBe("PB-SSH-BRUTEFORCE");
    const before = await db.playbook.findUniqueOrThrow({ where: { id: p.id }, include: { steps: true, revisions: true } });
    expect((await seedPlaybooks(db, tenantId)).find((o) => o.code === "PB-SSH-BRUTEFORCE")?.outcome).toBe("PRESERVED_PUBLISHED");
    expect(await db.playbook.findUniqueOrThrow({ where: { id: p.id }, include: { steps: true, revisions: true } })).toEqual(before);
  });
});
