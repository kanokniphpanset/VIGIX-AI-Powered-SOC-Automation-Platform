import { PrismaClient, Prisma } from "@prisma/client";
import { randomUUID } from "crypto";
import { AtomicWorkflow } from "../src/infrastructure/database/postgres/AtomicWorkflow";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaPlaybookRevisionRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRevisionRepository.prisma";
import { PlaybookContent } from "../src/domain/playbook/repositories/IPlaybookRevisionRepository";
import { PlaybookSelector } from "../src/application/recommendation/services/PlaybookSelector";
import { PublishPlaybookRevisionUseCase } from "../src/application/playbook/use-cases/PublishPlaybookRevision.usecase";
import { RollbackPlaybookRevisionUseCase } from "../src/application/playbook/use-cases/RollbackPlaybookRevision.usecase";
import { PlaybookPublicationInput } from "../src/application/playbook/use-cases/PlaybookPublication";
import { IPlaybookAuditRecorder } from "../src/application/playbook/ports/IPlaybookAuditRecorder";
import { IPlaybookPublicationListener, PlaybookPublishedEvent } from "../src/application/playbook/ports/IPlaybookPublicationListener";

/**
 * Phase 1D STEP 3 — publish / rollback use cases on real PostgreSQL (AtomicWorkflow + DB triggers). Opt-in only, against
 * the dedicated migrated Phase 1D database. Tenants are named "Phase1D tenant …" so the backfill suite excludes them.
 */
const url = process.env.PHASE1D_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

jest.setTimeout(60000);

type Status = Prisma.PlaybookRevisionCreateInput["status"];
/** Publisher used by default (STEP 6: SOC / IR_TEAM publish directly). */
const PUBLISHER = { id: "soc-9", role: "SOC", principalType: "HUMAN" as const };

suite("Phase 1D — publish / rollback use cases", () => {
  let db: PrismaClient;
  let atomic: AtomicWorkflow;
  let tenantA: string;
  let tenantB: string;
  let events: PlaybookPublishedEvent[];
  let listener: IPlaybookPublicationListener;

  const contentV1 = (code: string): PlaybookContent => ({
    code, name: `Playbook ${code}`, description: null, triggerConditions: { scope: "INCIDENT" }, n8nWorkflowId: null,
    playbookStatus: "ACTIVE", version: "1.0", steps: [{ stepOrder: 1, title: "Contain the host", description: null }],
  });
  /** Deliberately different in every projected field; steps stored out of order. */
  const contentVn = (code: string, n: number): PlaybookContent => ({
    code, name: `Playbook ${code} v${n}`, description: `revision ${n}`, triggerConditions: { scope: "INCIDENT", incidentType: `TYPE_${code}`, nested: { b: n, a: [1, 2] } },
    n8nWorkflowId: `wf-${n}`, playbookStatus: "ACTIVE", version: `${n}.0`,
    steps: [
      { stepOrder: 3, title: `v${n} eradicate`, description: "third" },
      { stepOrder: 1, title: `v${n} isolate`, description: null },
      { stepOrder: 2, title: `v${n} collect`, description: "second" },
    ],
  });

  /** Playbook with revision 1 PUBLISHED (pointer set), as the backfill leaves every existing playbook. */
  async function playbookWithV1(tenantId: string) {
    const code = `T1D3-${randomUUID()}`;
    return db.$transaction(async (tx) => {
      const playbook = await tx.playbook.create({ data: { tenantId, code, name: `Playbook ${code}`, version: "1.0", triggerConditions: { scope: "INCIDENT" }, steps: { create: [{ stepOrder: 1, title: "Contain the host", description: null }] } } });
      const rev1 = await tx.playbookRevision.create({ data: { tenantId, playbookId: playbook.id, revisionNumber: 1, version: "1.0", status: "PUBLISHED", content: contentV1(code) as never, createdBy: "author-1", publishedBy: "admin-0", publishedAt: new Date(Date.now() - 60_000) } });
      await tx.playbook.update({ where: { id: playbook.id }, data: { publishedRevisionId: rev1.id } });
      return { playbook, rev1, code };
    });
  }
  async function addRevision(tenantId: string, playbookId: string, code: string, n: number, status: Status, extra: Partial<Prisma.PlaybookRevisionUncheckedCreateInput> = {}) {
    return db.playbookRevision.create({ data: { tenantId, playbookId, revisionNumber: n, version: `${n}.0`, status, content: contentVn(code, n) as never, createdBy: "author-1", ...extra } });
  }
  /** v1 PUBLISHED + v2 DRAFT (created by author-1). */
  async function withDraftV2(tenantId = tenantA) {
    const base = await playbookWithV1(tenantId);
    const rev2 = await addRevision(tenantId, base.playbook.id, base.code, 2, "DRAFT");
    return { ...base, rev2 };
  }

  /** Everything a publish / rollback may touch, for "nothing changed" assertions. */
  async function snapshot(playbookId: string) {
    const playbook = await db.playbook.findUniqueOrThrow({ where: { id: playbookId } });
    const steps = await db.playbookStep.findMany({ where: { playbookId }, orderBy: { stepOrder: "asc" }, select: { stepOrder: true, title: true, description: true } });
    const revisions = await db.playbookRevision.findMany({ where: { playbookId }, orderBy: { revisionNumber: "asc" } });
    const audit = await db.auditLog.findMany({ where: { entity: "PlaybookRevision", entityId: { in: revisions.map((r) => r.id) } } });
    const fields = playbook;
    return { fields, steps, revisions: revisions.map(({ updatedAt: _r, ...r }) => r), audit };
  }
  const audits = async (revisionIds: string[]) =>
    db.auditLog.findMany({ where: { entity: "PlaybookRevision", entityId: { in: revisionIds } }, orderBy: { createdAt: "asc" } });
  async function expectProjection(playbookId: string, c: PlaybookContent, code: string) {
    const p = await db.playbook.findUniqueOrThrow({ where: { id: playbookId }, include: { steps: { orderBy: { stepOrder: "asc" } } } });
    expect({ code: p.code, name: p.name, description: p.description, triggerConditions: p.triggerConditions, n8nWorkflowId: p.n8nWorkflowId, status: p.status, version: p.version })
      .toEqual({ code, name: c.name, description: c.description, triggerConditions: c.triggerConditions, n8nWorkflowId: c.n8nWorkflowId, status: c.playbookStatus, version: c.version });
    expect(p.steps.map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })))
      .toEqual([...c.steps].sort((a, b) => a.stepOrder - b.stepOrder));
  }

  function build(opts: { repo?: PrismaPlaybookRevisionRepository; audit?: IPlaybookAuditRecorder } = {}) {
    const repo = opts.repo ?? new PrismaPlaybookRevisionRepository(atomic.prisma);
    const audit = opts.audit ?? new AuditLogger(atomic.prisma);
    const deferred = atomic.defer(listener, ["published"]);
    return {
      publish: atomic.wrap(new PublishPlaybookRevisionUseCase(repo, audit, deferred), "playbook"),
      rollback: atomic.wrap(new RollbackPlaybookRevisionUseCase(repo, audit, deferred), "playbook"),
    };
  }
  const input = (tenantId: string, playbookId: string, revisionId: string, actor: PlaybookPublicationInput["actor"] = PUBLISHER): PlaybookPublicationInput =>
    ({ tenantId, id: playbookId, revisionId, actor, reason: "test" });

  beforeAll(async () => {
    if (!url || !/^vigix_phase1d_test_[a-z0-9_]+$/.test(new URL(url).pathname.slice(1))) {
      throw new Error("Dedicated Phase 1D database required; runtime/evaluation targets are forbidden");
    }
    db = new PrismaClient({ datasources: { db: { url } } });
    atomic = new AtomicWorkflow(db);
    tenantA = (await db.tenant.create({ data: { name: "Phase1D tenant publish A" } })).id;
    tenantB = (await db.tenant.create({ data: { name: "Phase1D tenant publish B" } })).id;
  });
  beforeEach(() => {
    events = [];
    listener = { published: async (e) => { events.push(e); } };
  });
  afterAll(async () => db?.$disconnect());

  describe("publish", () => {
    test("valid publish: v1 SUPERSEDED, v2 PUBLISHED, pointer, projection, audit, after-commit event", async () => {
      const { playbook, rev1, rev2, code } = await withDraftV2();
      const result = await build().publish.execute(input(tenantA, playbook.id, rev2.id));
      expect(result.isSuccess).toBe(true);

      const after = await snapshot(playbook.id);
      const [r1, r2] = after.revisions;
      expect(r1).toMatchObject({ status: "SUPERSEDED", publishedBy: "admin-0", publishedAt: rev1.publishedAt });
      expect(r2).toMatchObject({ status: "PUBLISHED", publishedBy: PUBLISHER.id, createdBy: "author-1", content: rev2.content, version: "2.0", revisionNumber: 2 });
      expect(r2.publishedAt).toEqual(result.value.publishedAt);
      expect(after.fields.publishedRevisionId).toBe(rev2.id);
      await expectProjection(playbook.id, contentVn(code, 2), code);

      const logs = await audits([rev1.id, rev2.id]);
      expect(logs.map((l) => [l.action, l.entityId])).toEqual([["PLAYBOOK_REVISION_SUPERSEDED", rev1.id], ["PLAYBOOK_REVISION_PUBLISHED", rev2.id]]);
      expect(logs.every((l) => l.actor === PUBLISHER.id && l.tenantId === tenantA)).toBe(true);
      expect(logs[1].metadata).toMatchObject({
        playbookId: playbook.id, revisionId: rev2.id, version: "2.0", reason: "test", actor: PUBLISHER.id, principalType: "HUMAN", previousRevisionId: rev1.id,
        before: { status: "DRAFT", publishedBy: null, publishedAt: null, publishedRevisionId: rev1.id },
        after: { status: "PUBLISHED", publishedBy: PUBLISHER.id, publishedRevisionId: rev2.id },
      });
      expect(logs[0].metadata).toMatchObject({ revisionId: rev1.id, version: "1.0", before: { status: "PUBLISHED" }, after: { status: "SUPERSEDED", publishedRevisionId: rev2.id } });
      expect(events).toEqual([expect.objectContaining({ kind: "PUBLISH", playbookId: playbook.id, revisionId: rev2.id, previousRevisionId: rev1.id, version: "2.0" })]);
    });

    test("existing runtime readers (repository + PlaybookSelector) see the published revision", async () => {
      const { playbook, rev2, code } = await withDraftV2();
      await build().publish.execute(input(tenantA, playbook.id, rev2.id));
      const p = await new PrismaPlaybookRepository(db).findById(playbook.id, tenantA);
      expect(p!.version).toBe("2.0");
      expect(p!.steps.map((s) => s.title)).toEqual(["v2 isolate", "v2 collect", "v2 eradicate"]);
      expect(new PlaybookSelector().incidentPlaybooks([p!]).map((x) => x.code)).toEqual([code]);
    });

    // Legacy review states from the removed approval flow never go live.
    test.each(["IN_REVIEW", "APPROVED", "REJECTED", "SUPERSEDED"] as const)("target %s → INVALID_REVISION_STATUS, nothing changes", async (status) => {
      const { playbook, code } = await playbookWithV1(tenantA);
      const target = await addRevision(tenantA, playbook.id, code, 2, status, { approvedBy: "reviewer-1" });
      const before = await snapshot(playbook.id);
      const result = await build().publish.execute(input(tenantA, playbook.id, target.id));
      expect(result.isFailure && result.error).toBe("INVALID_REVISION_STATUS");
      expect(await snapshot(playbook.id)).toEqual(before);
      expect(events).toEqual([]);
    });

    test("already PUBLISHED → ALREADY_PUBLISHED, no mutation, no audit", async () => {
      const { playbook, rev1 } = await playbookWithV1(tenantA);
      const before = await snapshot(playbook.id);
      const result = await build().publish.execute(input(tenantA, playbook.id, rev1.id));
      expect(result.isFailure && result.error).toBe("ALREADY_PUBLISHED");
      expect(await snapshot(playbook.id)).toEqual(before);
      expect(before.audit).toEqual([]);
    });

    test("no four-eyes / approval: the draft's own creator (SOC) and IR_TEAM publish directly", async () => {
      const a = await withDraftV2();
      const asCreator = await build().publish.execute(input(tenantA, a.playbook.id, a.rev2.id, { id: "author-1", role: "SOC", principalType: "HUMAN" }));
      expect(asCreator.isSuccess).toBe(true);
      const b = await withDraftV2();
      const asIr = await build().publish.execute(input(tenantA, b.playbook.id, b.rev2.id, { id: "ir-1", role: "IR_TEAM", principalType: "HUMAN" }));
      expect(asIr.isSuccess).toBe(true);
      expect((await db.playbook.findUniqueOrThrow({ where: { id: b.playbook.id } })).publishedRevisionId).toBe(b.rev2.id);
    });

    test("service principals, admin and other roles cannot publish", async () => {
      const { playbook, rev2 } = await withDraftV2();
      const before = await snapshot(playbook.id);
      const { publish } = build();
      const service = await publish.execute(input(tenantA, playbook.id, rev2.id, { id: "service:ai-orchestrator", principalType: "SERVICE" }));
      expect(service.isFailure && service.error).toBe("SERVICE_PRINCIPAL_FORBIDDEN");
      const serviceWithRole = await publish.execute(input(tenantA, playbook.id, rev2.id, { id: "service:x", role: "admin", principalType: "SERVICE" }));
      expect(serviceWithRole.isFailure && serviceWithRole.error).toBe("SERVICE_PRINCIPAL_FORBIDDEN");
      const admin = await publish.execute(input(tenantA, playbook.id, rev2.id, { id: "admin-1", role: "admin", principalType: "HUMAN" }));
      expect(admin.isFailure && admin.error).toBe("ROLE_FORBIDDEN");
      const viewer = await publish.execute(input(tenantA, playbook.id, rev2.id, { id: "v-1", role: "VIEWER", principalType: "HUMAN" }));
      expect(viewer.isFailure && viewer.error).toBe("ROLE_FORBIDDEN");
      expect(await snapshot(playbook.id)).toEqual(before);
    });

    test("tenant mismatch: other tenant's playbook or revision is not found, nothing changes", async () => {
      const a = await withDraftV2(tenantA);
      const b = await withDraftV2(tenantB);
      const beforeA = await snapshot(a.playbook.id);
      const beforeB = await snapshot(b.playbook.id);
      const { publish } = build();
      const foreignPlaybook = await publish.execute(input(tenantB, a.playbook.id, a.rev2.id));
      expect(foreignPlaybook.isFailure && foreignPlaybook.error).toBe("PLAYBOOK_NOT_FOUND");
      const foreignRevision = await publish.execute(input(tenantA, a.playbook.id, b.rev2.id));
      expect(foreignRevision.isFailure && foreignRevision.error).toBe("REVISION_NOT_FOUND");
      expect(await snapshot(a.playbook.id)).toEqual(beforeA);
      expect(await snapshot(b.playbook.id)).toEqual(beforeB);
    });

    test("playbook mismatch: revision of another playbook → REVISION_PLAYBOOK_MISMATCH", async () => {
      const a = await withDraftV2();
      const other = await withDraftV2();
      const before = [await snapshot(a.playbook.id), await snapshot(other.playbook.id)];
      const result = await build().publish.execute(input(tenantA, a.playbook.id, other.rev2.id));
      expect(result.isFailure && result.error).toBe("REVISION_PLAYBOOK_MISMATCH");
      expect([await snapshot(a.playbook.id), await snapshot(other.playbook.id)]).toEqual(before);
    });

    test("content.code differing from playbooks.code → PLAYBOOK_CODE_MISMATCH; code never changed", async () => {
      const { playbook, code } = await playbookWithV1(tenantA);
      const target = await db.playbookRevision.create({ data: { tenantId: tenantA, playbookId: playbook.id, revisionNumber: 2, version: "2.0", status: "DRAFT", content: contentVn("OTHER-CODE", 2) as never, createdBy: "author-1" } });
      const before = await snapshot(playbook.id);
      const result = await build().publish.execute(input(tenantA, playbook.id, target.id));
      expect(result.isFailure && result.error).toBe("PLAYBOOK_CODE_MISMATCH");
      expect(await snapshot(playbook.id)).toEqual(before);
      expect(before.fields.code).toBe(code);
    });
  });

  describe("rollback", () => {
    test("valid rollback to v1: publishedBy/publishedAt refreshed, history fields untouched, projection back to v1", async () => {
      const { playbook, rev1, rev2, code } = await withDraftV2();
      const { publish, rollback } = build();
      expect((await publish.execute(input(tenantA, playbook.id, rev2.id))).isSuccess).toBe(true);
      const beforeRollback = await db.playbookRevision.findUniqueOrThrow({ where: { id: rev1.id } });

      const rollbackActor = { id: "admin-8", role: "IR_TEAM", principalType: "HUMAN" as const };
      const result = await rollback.execute(input(tenantA, playbook.id, rev1.id, rollbackActor));
      expect(result.isSuccess).toBe(true);

      const [r1, r2] = (await snapshot(playbook.id)).revisions;
      expect(r1).toMatchObject({ status: "PUBLISHED", publishedBy: "admin-8", createdBy: rev1.createdBy, createdAt: rev1.createdAt, content: rev1.content, revisionNumber: 1, version: "1.0" });
      expect(r1.publishedAt!.getTime()).toBeGreaterThan(beforeRollback.publishedAt!.getTime());
      expect(r2).toMatchObject({ status: "SUPERSEDED", publishedBy: PUBLISHER.id });
      expect((await db.playbook.findUniqueOrThrow({ where: { id: playbook.id } })).publishedRevisionId).toBe(rev1.id);
      await expectProjection(playbook.id, contentV1(code), code);

      const logs = (await audits([rev1.id, rev2.id])).slice(2);
      expect(logs.map((l) => [l.action, l.entityId])).toEqual([["PLAYBOOK_REVISION_SUPERSEDED", rev2.id], ["PLAYBOOK_REVISION_ROLLED_BACK", rev1.id]]);
      expect(logs[1].metadata).toMatchObject({
        revisionId: rev1.id, version: "1.0", actor: "admin-8", principalType: "HUMAN", previousRevisionId: rev2.id,
        before: { status: "SUPERSEDED", publishedBy: "admin-0", publishedAt: beforeRollback.publishedAt!.toISOString(), publishedRevisionId: rev2.id },
        after: { status: "PUBLISHED", publishedBy: "admin-8", publishedAt: result.value.publishedAt.toISOString(), publishedRevisionId: rev1.id },
      });
      expect(events.map((e) => e.kind)).toEqual(["PUBLISH", "ROLLBACK"]);
    });

    test("invalid rollback targets: DRAFT, current PUBLISHED, never-published SUPERSEDED; nothing changes", async () => {
      const { playbook, rev1, rev2, code } = await withDraftV2();
      const neverPublished = await addRevision(tenantA, playbook.id, code, 3, "SUPERSEDED", { publishedAt: null });
      const before = await snapshot(playbook.id);
      const { rollback } = build();
      const approved = await rollback.execute(input(tenantA, playbook.id, rev2.id));
      expect(approved.isFailure && approved.error).toBe("INVALID_REVISION_STATUS");
      const current = await rollback.execute(input(tenantA, playbook.id, rev1.id));
      expect(current.isFailure && current.error).toBe("INVALID_REVISION_STATUS");
      const never = await rollback.execute(input(tenantA, playbook.id, neverPublished.id));
      expect(never.isFailure && never.error).toBe("NEVER_PUBLISHED");
      expect(await snapshot(playbook.id)).toEqual(before);
      expect(events).toEqual([]);
    });

    test("rollback is SOC / IR_TEAM human only (creator allowed: no four-eyes)", async () => {
      const { playbook, rev1, rev2 } = await withDraftV2();
      const { publish, rollback } = build();
      await publish.execute(input(tenantA, playbook.id, rev2.id));
      const before = await snapshot(playbook.id);
      const service = await rollback.execute(input(tenantA, playbook.id, rev1.id, { id: "service:x", role: "admin", principalType: "SERVICE" }));
      expect(service.isFailure && service.error).toBe("SERVICE_PRINCIPAL_FORBIDDEN");
      const admin = await rollback.execute(input(tenantA, playbook.id, rev1.id, { id: "admin-1", role: "admin", principalType: "HUMAN" }));
      expect(admin.isFailure && admin.error).toBe("ROLE_FORBIDDEN");
      const foreignTenant = await rollback.execute(input(tenantB, playbook.id, rev1.id));
      expect(foreignTenant.isFailure && foreignTenant.error).toBe("PLAYBOOK_NOT_FOUND");
      expect(await snapshot(playbook.id)).toEqual(before);
      const creator = await rollback.execute(input(tenantA, playbook.id, rev1.id, { id: "author-1", role: "SOC", principalType: "HUMAN" }));
      expect(creator.isSuccess).toBe(true);
    });
  });

  describe("atomicity", () => {
    test("projection mismatch after writes → PROJECTION_MISMATCH and full rollback", async () => {
      class TamperingRepo extends PrismaPlaybookRevisionRepository {
        async projectContent(playbookId: string, version: string, content: PlaybookContent) {
          await super.projectContent(playbookId, version, { ...content, steps: content.steps.map((s) => ({ ...s, title: `${s.title} (tampered)` })) });
        }
      }
      const { playbook, rev2 } = await withDraftV2();
      const before = await snapshot(playbook.id);
      const result = await build({ repo: new TamperingRepo(atomic.prisma) }).publish.execute(input(tenantA, playbook.id, rev2.id));
      expect(result.isFailure && result.error).toBe("PROJECTION_MISMATCH");
      expect(await snapshot(playbook.id)).toEqual(before);
      expect(events).toEqual([]);
    });

    test("publication invariant violated (pointer not moved) → SET CONSTRAINTS error reaches the caller, everything rolled back", async () => {
      class NoPointerRepo extends PrismaPlaybookRevisionRepository {
        async setPublishedPointer() { /* skipped on purpose */ }
      }
      const { playbook, rev2 } = await withDraftV2();
      const before = await snapshot(playbook.id);
      await expect(build({ repo: new NoPointerRepo(atomic.prisma) }).publish.execute(input(tenantA, playbook.id, rev2.id)))
        .rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
      expect(await snapshot(playbook.id)).toEqual(before);
      expect(events).toEqual([]);
    });

    test("audit failure → no publish: revision states, pointer, projection and the first audit row all rolled back", async () => {
      const real = new AuditLogger(atomic.prisma);
      const failing: IPlaybookAuditRecorder = {
        record: async (entry) => {
          if (entry.action === "PLAYBOOK_REVISION_PUBLISHED") throw new Error("audit store unavailable");
          await real.record(entry);
        },
      };
      const { playbook, rev2 } = await withDraftV2();
      const before = await snapshot(playbook.id);
      await expect(build({ audit: failing }).publish.execute(input(tenantA, playbook.id, rev2.id))).rejects.toThrow("audit store unavailable");
      expect(await snapshot(playbook.id)).toEqual(before);
      expect(events).toEqual([]);
    });

    test("after-commit listener runs only after COMMIT and sees committed state", async () => {
      const { playbook, rev2 } = await withDraftV2();
      let seen: string | undefined;
      listener = { published: async (e) => { events.push(e); seen = (await db.playbookRevision.findUniqueOrThrow({ where: { id: e.revisionId } })).status; } };
      const result = await build().publish.execute(input(tenantA, playbook.id, rev2.id));
      expect(result.isSuccess).toBe(true);
      expect(events).toHaveLength(1);
      expect(seen).toBe("PUBLISHED"); // read on a separate connection: only visible after commit
    });
  });

  describe("concurrency (playbook row lock)", () => {
    test("two concurrent publishes of the same revision: one succeeds, the other is ALREADY_PUBLISHED", async () => {
      const { playbook, rev1, rev2 } = await withDraftV2();
      const { publish } = build();
      const results = await Promise.all([
        publish.execute(input(tenantA, playbook.id, rev2.id)),
        publish.execute(input(tenantA, playbook.id, rev2.id, { id: "ir-7", role: "IR_TEAM", principalType: "HUMAN" })),
      ]);
      expect(results.filter((r) => r.isSuccess)).toHaveLength(1);
      expect(results.filter((r) => r.isFailure).map((r) => r.error)).toEqual(["ALREADY_PUBLISHED"]);
      expect(await audits([rev1.id, rev2.id])).toHaveLength(2);
      expect(events).toHaveLength(1);
    });

    test("concurrent publishes of two approved revisions serialize: exactly one PUBLISHED, pointer and projection match it", async () => {
      const { playbook, rev1, rev2, code } = await withDraftV2();
      const rev3 = await addRevision(tenantA, playbook.id, code, 3, "DRAFT");
      const { publish } = build();
      const results = await Promise.all([publish.execute(input(tenantA, playbook.id, rev2.id)), publish.execute(input(tenantA, playbook.id, rev3.id))]);
      expect(results.every((r) => r.isSuccess)).toBe(true);

      const revisions = await db.playbookRevision.findMany({ where: { playbookId: playbook.id } });
      const published = revisions.filter((r) => r.status === "PUBLISHED");
      expect(published).toHaveLength(1);
      expect(revisions.filter((r) => r.status === "SUPERSEDED").map((r) => r.id).sort()).toEqual([rev1.id, rev2.id, rev3.id].filter((id) => id !== published[0].id).sort());
      expect((await db.playbook.findUniqueOrThrow({ where: { id: playbook.id } })).publishedRevisionId).toBe(published[0].id);
      await expectProjection(playbook.id, contentVn(code, published[0].revisionNumber), code);
      // The second publisher superseded the first one's revision, not v1 again.
      const second = results.map((r) => r.value).find((v) => v.revisionId === published[0].id)!;
      expect(second.previousRevisionId).not.toBe(rev1.id);
      expect(await audits([rev1.id, rev2.id, rev3.id])).toHaveLength(4);
    });
  });
});
