import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { PrismaClient } from "@prisma/client";
import { randomUUID } from "crypto";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildPlaybookRoutes } from "../src/presentation/http/routes/playbook.routes";
import { PlaybookController } from "../src/presentation/http/controllers/PlaybookController";
import { AtomicWorkflow } from "../src/infrastructure/database/postgres/AtomicWorkflow";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { CreatePlaybookUseCase } from "../src/application/playbook/use-cases/CreatePlaybook.usecase";
import { UpdatePlaybookUseCase } from "../src/application/playbook/use-cases/UpdatePlaybook.usecase";
import { GetPlaybookUseCase } from "../src/application/playbook/use-cases/GetPlaybook.usecase";
import { ListPlaybooksUseCase } from "../src/application/playbook/use-cases/ListPlaybooks.usecase";
import { DeletePlaybookUseCase } from "../src/application/playbook/use-cases/DeletePlaybook.usecase";

/**
 * Phase 1D STEP 4 — PUT / DELETE /api/playbooks cannot bypass the revision lifecycle. Real routes + JWT + controller +
 * AtomicWorkflow-wrapped use cases (as wired in the container) on the dedicated migrated Phase 1D database.
 * Tenants are named "Phase1D tenant …" so the backfill suite excludes them.
 */
const url = process.env.PHASE1D_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

jest.setTimeout(60000);

suite("Phase 1D — playbook mutation guard (PUT / DELETE)", () => {
  let db: PrismaClient;
  let server: Server;
  let base = "";
  let tenantA: string;
  let tenantB: string;

  const content = (code: string) => ({
    code, name: `Playbook ${code}`, description: null, triggerConditions: { scope: "INCIDENT", incidentType: `TYPE_${code}` }, n8nWorkflowId: null,
    playbookStatus: "ACTIVE", version: "1.0", steps: [{ stepOrder: 1, title: "Contain the host", description: null }],
  });
  async function playbook(tenantId: string, revision: "PUBLISHED" | "DRAFT" | null) {
    const code = `T1D4-${randomUUID()}`;
    return db.$transaction(async (tx) => {
      const p = await tx.playbook.create({ data: { tenantId, code, name: `Playbook ${code}`, version: "1.0", status: "ACTIVE", triggerConditions: { scope: "INCIDENT", incidentType: `TYPE_${code}` }, steps: { create: [{ stepOrder: 1, title: "Contain the host", description: null }] } } });
      if (revision) {
        const r = await tx.playbookRevision.create({ data: { tenantId, playbookId: p.id, revisionNumber: 1, version: "1.0", status: revision, content: content(code), createdBy: "author-1", ...(revision === "PUBLISHED" ? { publishedBy: "admin-0", publishedAt: new Date() } : {}) } });
        if (revision === "PUBLISHED") await tx.playbook.update({ where: { id: p.id }, data: { publishedRevisionId: r.id } });
      }
      return { id: p.id, code };
    });
  }
  /** playbooks row, playbook_steps (with ids), revisions, pointer and every audit row of the tenant. */
  async function snapshot(playbookId: string, tenantId: string) {
    return {
      playbook: await db.playbook.findUnique({ where: { id: playbookId } }),
      steps: await db.playbookStep.findMany({ where: { playbookId }, orderBy: { stepOrder: "asc" } }),
      revisions: await db.playbookRevision.findMany({ where: { playbookId }, orderBy: { revisionNumber: "asc" } }),
      audit: await db.auditLog.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    };
  }

  const token = (tenantId: string, role: string) => `Bearer ${signToken({ id: `u-${role}`, tenantId, role })}`;
  const call = async (method: string, path: string, body: unknown, tenantId: string, role = "admin") => {
    const res = await fetch(`${base}/api/playbooks${path}`, {
      method, headers: { "content-type": "application/json", authorization: token(tenantId, role) }, body: JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> };
  };

  beforeAll(async () => {
    if (!url || !/^vigix_phase1d_test_[a-z0-9_]+$/.test(new URL(url).pathname.slice(1))) {
      throw new Error("Dedicated Phase 1D database required; runtime/evaluation targets are forbidden");
    }
    db = new PrismaClient({ datasources: { db: { url } } });
    tenantA = (await db.tenant.create({ data: { name: "Phase1D tenant guard A" } })).id;
    tenantB = (await db.tenant.create({ data: { name: "Phase1D tenant guard B" } })).id;

    const atomic = new AtomicWorkflow(db);
    const repo = new PrismaPlaybookRepository(atomic.prisma);
    const audit = new AuditLogger(atomic.prisma);
    const controller = new PlaybookController(
      atomic.wrap(new CreatePlaybookUseCase(repo, audit), "playbook"),
      atomic.wrap(new UpdatePlaybookUseCase(repo, audit), "playbook"),
      new GetPlaybookUseCase(repo),
      new ListPlaybooksUseCase(repo),
      atomic.wrap(new DeletePlaybookUseCase(repo, audit), "playbook"),
    );
    const app = express();
    app.use(express.json());
    app.use("/api/playbooks", buildPlaybookRoutes(controller));
    server = app.listen(0);
    await new Promise<void>((r) => server.once("listening", () => r()));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    await db?.$disconnect();
  });

  describe("PUT", () => {
    test.each([
      ["metadata", { name: "Renamed", description: "edited" }],
      ["status (deactivate)", { status: "DEPRECATED" }],
      ["version", { version: "9.9" }],
      ["incident type (trigger_conditions)", { incidentType: "OTHER" }],
      ["steps", { steps: [{ stepOrder: 1, title: "Replaced" }, { stepOrder: 2, title: "Added" }] }],
      ["empty body", {}],
    ])("published playbook, %s → 409 PLAYBOOK_PUBLISHED_IMMUTABLE; playbook, steps, revision, pointer, audit unchanged", async (_label, body) => {
      const p = await playbook(tenantA, "PUBLISHED");
      const before = await snapshot(p.id, tenantA);
      expect(await call("PUT", `/${p.id}`, body, tenantA)).toEqual({ status: 409, body: { error: "PLAYBOOK_PUBLISHED_IMMUTABLE" } });
      expect(await snapshot(p.id, tenantA)).toEqual(before);
      expect(before.playbook!.publishedRevisionId).toBe(before.revisions[0].id);
    });

    // STEP 5: a not-yet-published playbook with revisions is revision-managed too (PUT could otherwise activate a draft).
    test.each([["metadata", { name: "Draft-era edit" }], ["activate", { status: "ACTIVE" }]])(
      "non-published playbook with a DRAFT revision, %s → 409 PLAYBOOK_REVISION_MANAGED; nothing changes", async (_label, body) => {
        const p = await playbook(tenantA, "DRAFT");
        const before = await snapshot(p.id, tenantA);
        expect(await call("PUT", `/${p.id}`, body, tenantA)).toEqual({ status: 409, body: { error: "PLAYBOOK_REVISION_MANAGED" } });
        expect(await snapshot(p.id, tenantA)).toEqual(before);
      });

    test("playbook without revisions (pre-revision / created via POST): edit unchanged", async () => {
      const p = await playbook(tenantA, null);
      const r = await call("PUT", `/${p.id}`, { name: "Legacy edit", steps: [{ stepOrder: 1, title: "New step" }] }, tenantA);
      expect(r).toMatchObject({ status: 200, body: { name: "Legacy edit" } });
      expect((await db.playbookStep.findMany({ where: { playbookId: p.id } })).map((s) => s.title)).toEqual(["New step"]);
    });

    test("tenant isolation: another tenant's published playbook → 404, unchanged", async () => {
      const p = await playbook(tenantA, "PUBLISHED");
      const before = await snapshot(p.id, tenantA);
      expect(await call("PUT", `/${p.id}`, { name: "x" }, tenantB)).toEqual({ status: 404, body: { error: "PLAYBOOK_NOT_FOUND" } });
      expect(await snapshot(p.id, tenantA)).toEqual(before);
    });

    test("authorization unchanged: VIEWER → 403, unchanged", async () => {
      const p = await playbook(tenantA, null);
      const before = await snapshot(p.id, tenantA);
      expect((await call("PUT", `/${p.id}`, { name: "x" }, tenantA, "VIEWER")).status).toBe(403);
      expect(await snapshot(p.id, tenantA)).toEqual(before);
    });
  });

  describe("DELETE", () => {
    // STEP 6: a draft-only (never published) playbook may be deleted — see Phase1DCreateLifecycle.
    test.each(["PUBLISHED"] as const)("playbook with %s revision history → 409 PLAYBOOK_REVISION_HISTORY_EXISTS (not a 500); nothing deleted", async (status) => {
      const p = await playbook(tenantA, status);
      const before = await snapshot(p.id, tenantA);
      expect(before.revisions).toHaveLength(1);
      expect(await call("DELETE", `/${p.id}`, { reason: "cleanup" }, tenantA)).toEqual({ status: 409, body: { error: "PLAYBOOK_REVISION_HISTORY_EXISTS" } });
      const after = await snapshot(p.id, tenantA);
      expect(after).toEqual(before);
      expect(after.playbook).not.toBeNull();
      expect(after.steps).toHaveLength(1);
    });

    test("playbook without revisions: delete unchanged (200, steps removed, DELETE_PLAYBOOK audited)", async () => {
      const p = await playbook(tenantA, null);
      expect(await call("DELETE", `/${p.id}`, { reason: "cleanup" }, tenantA)).toMatchObject({ status: 200, body: { deleted: true, id: p.id, code: p.code } });
      expect(await db.playbook.findUnique({ where: { id: p.id } })).toBeNull();
      expect(await db.playbookStep.count({ where: { playbookId: p.id } })).toBe(0);
      expect(await db.auditLog.findMany({ where: { tenantId: tenantA, entityId: p.id } })).toEqual([expect.objectContaining({ action: "DELETE_PLAYBOOK" })]);
    });

    test("tenant isolation and authorization: other tenant → 404, VIEWER → 403; nothing deleted", async () => {
      const p = await playbook(tenantA, "PUBLISHED");
      const before = await snapshot(p.id, tenantA);
      expect((await call("DELETE", `/${p.id}`, {}, tenantB)).status).toBe(404);
      expect((await call("DELETE", `/${p.id}`, {}, tenantA, "VIEWER")).status).toBe(403);
      expect(await snapshot(p.id, tenantA)).toEqual(before);
    });
  });
});
