import { PrismaClient, Prisma } from "@prisma/client";
import { randomUUID } from "crypto";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PlaybookSelector } from "../src/application/recommendation/services/PlaybookSelector";
import { AtomicWorkflow } from "../src/infrastructure/database/postgres/AtomicWorkflow";

/**
 * Phase 1D — playbook revision schema, backfill and DB-level immutability (migration 20261006030000_playbook_revisions).
 * Opt-in only, against a dedicated database migrated with `prisma migrate deploy` (never a runtime / evaluation DB).
 * The backfill checks read the playbooks that existed before the migration; every other test works in its own tenants.
 */
const url = process.env.PHASE1D_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

jest.setTimeout(30000);

suite("Phase 1D — playbook revisions on real PostgreSQL", () => {
  let db: PrismaClient;
  let tenantA: string;
  let tenantB: string;
  /** Every tenant this suite ever created (earlier runs included), so re-runs on the same DB stay correct. */
  let testTenantIds: string[] = [];
  const testTenants = () => testTenantIds;

  const content = (code: string, version: string, title = "Contain the host") => ({
    code, name: `Playbook ${code}`, description: null, triggerConditions: { scope: "INCIDENT" }, n8nWorkflowId: null,
    playbookStatus: "ACTIVE", version, steps: [{ stepOrder: 1, title, description: null }],
  });

  /** A playbook with revision 1 PUBLISHED and the pointer set, created in one transaction (as a publish would). */
  async function publishedPlaybook(tenantId: string) {
    const code = `T1D-${randomUUID()}`;
    return db.$transaction(async (tx) => {
      const playbook = await tx.playbook.create({ data: { tenantId, code, name: `Playbook ${code}`, triggerConditions: { scope: "INCIDENT" }, steps: { create: [{ stepOrder: 1, title: "Contain the host", description: null }] } } });
      const revision = await tx.playbookRevision.create({ data: { tenantId, playbookId: playbook.id, revisionNumber: 1, version: "1.0", status: "PUBLISHED", content: content(code, "1.0"), createdBy: "author-1", publishedBy: "admin-1", publishedAt: new Date() } });
      await tx.playbook.update({ where: { id: playbook.id }, data: { publishedRevisionId: revision.id } });
      return { playbook, revision, code };
    });
  }
  const revision = (playbookId: string, tenantId: string, n: number, status: Prisma.PlaybookRevisionCreateInput["status"], code = "X") =>
    db.playbookRevision.create({ data: { tenantId, playbookId, revisionNumber: n, version: `${n}.0`, status, content: content(code, `${n}.0`, `step v${n}`), createdBy: "author-1" } });

  beforeAll(async () => {
    if (!url || !/^vigix_phase1d_test_[a-z0-9_]+$/.test(new URL(url).pathname.slice(1))) {
      throw new Error("Dedicated Phase 1D database required; runtime/evaluation targets are forbidden");
    }
    db = new PrismaClient({ datasources: { db: { url } } });
    tenantA = (await db.tenant.create({ data: { name: "Phase1D tenant A" } })).id;
    tenantB = (await db.tenant.create({ data: { name: "Phase1D tenant B" } })).id;
    testTenantIds = (await db.tenant.findMany({ where: { name: { startsWith: "Phase1D tenant" } }, select: { id: true } })).map((t) => t.id);
  });
  // Other Phase 1D suites run in parallel and create their tenants later: refresh before every test.
  beforeEach(async () => {
    testTenantIds = (await db.tenant.findMany({ where: { name: { startsWith: "Phase1D tenant" } }, select: { id: true } })).map((t) => t.id);
  });
  afterAll(async () => db?.$disconnect());

  describe("backfill of the playbooks that existed before the migration", () => {
    const existing = () => db.playbook.findMany({ where: { tenantId: { notIn: testTenants() } }, include: { steps: true, publishedRevision: true } });

    test("every existing playbook points to its revision 1, PUBLISHED", async () => {
      const playbooks = await existing();
      expect(playbooks.length).toBeGreaterThan(0);
      for (const p of playbooks) {
        expect(p.publishedRevisionId).not.toBeNull();
        expect(p.publishedRevision).toMatchObject({ playbookId: p.id, revisionNumber: 1, status: "PUBLISHED", tenantId: p.tenantId, version: p.version ?? "1.0" });
      }
      const revisions = await db.playbookRevision.findMany({ where: { tenantId: { notIn: testTenants() } } });
      expect(revisions).toHaveLength(playbooks.length);
    });

    test("revision content is exactly the playbook as it was: fields, triggerConditions, steps and their order", async () => {
      for (const p of await existing()) {
        expect(p.publishedRevision!.content).toEqual({
          code: p.code, name: p.name, description: p.description, triggerConditions: p.triggerConditions, n8nWorkflowId: p.n8nWorkflowId,
          playbookStatus: p.status, version: p.version,
          steps: [...p.steps].sort((a, b) => a.stepOrder - b.stepOrder).map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })),
        });
      }
      const [{ steps, inContent }] = await db.$queryRaw<{ steps: bigint; inContent: bigint }[]>`
        SELECT (SELECT count(*) FROM playbook_steps s JOIN playbooks p ON p.id = s.playbook_id WHERE p.tenant_id <> ALL(${testTenants()})) AS steps,
               (SELECT COALESCE(sum(jsonb_array_length(content->'steps')), 0) FROM playbook_revisions WHERE tenant_id <> ALL(${testTenants()})) AS "inContent"`;
      expect(Number(inContent)).toBe(Number(steps));
    });
  });

  describe("DB trigger: published / approved / superseded revisions are immutable", () => {
    test("UPDATE of a PUBLISHED revision's content is rejected", async () => {
      const { revision: r } = await publishedPlaybook(tenantA);
      await expect(db.$executeRaw`UPDATE playbook_revisions SET content = '{"tampered": true}'::jsonb WHERE id = ${r.id}`).rejects.toThrow(/PLAYBOOK_REVISION_IMMUTABLE/);
      await expect(db.playbookRevision.update({ where: { id: r.id }, data: { content: { tampered: true } } })).rejects.toThrow(/PLAYBOOK_REVISION_IMMUTABLE/);
      expect((await db.playbookRevision.findUniqueOrThrow({ where: { id: r.id } })).content).toEqual(r.content);
    });

    test("version / identity cannot change, and a PUBLISHED revision cannot be sent back to DRAFT to edit it", async () => {
      const { revision: r } = await publishedPlaybook(tenantA);
      await expect(db.$executeRaw`UPDATE playbook_revisions SET version = '9.9' WHERE id = ${r.id}`).rejects.toThrow(/PLAYBOOK_REVISION_IMMUTABLE/);
      await expect(db.$executeRaw`UPDATE playbook_revisions SET revision_number = 7 WHERE id = ${r.id}`).rejects.toThrow(/PLAYBOOK_REVISION_IMMUTABLE/);
      await expect(db.$executeRaw`UPDATE playbook_revisions SET status = 'DRAFT' WHERE id = ${r.id}`).rejects.toThrow(/PLAYBOOK_REVISION_IMMUTABLE/);
    });

    test("APPROVED and SUPERSEDED content is frozen too; DRAFT and IN_REVIEW content stays editable", async () => {
      const { playbook } = await publishedPlaybook(tenantA);
      const approved = await revision(playbook.id, tenantA, 2, "APPROVED");
      const superseded = await revision(playbook.id, tenantA, 3, "SUPERSEDED");
      const draft = await revision(playbook.id, tenantA, 4, "DRAFT");
      const inReview = await revision(playbook.id, tenantA, 5, "IN_REVIEW");
      for (const r of [approved, superseded]) {
        await expect(db.$executeRaw`UPDATE playbook_revisions SET content = '{"x": 1}'::jsonb WHERE id = ${r.id}`).rejects.toThrow(/PLAYBOOK_REVISION_IMMUTABLE/);
      }
      for (const r of [draft, inReview]) {
        const updated = await db.playbookRevision.update({ where: { id: r.id }, data: { content: content("X", r.version, "edited step") } });
        expect((updated.content as { steps: { title: string }[] }).steps[0].title).toBe("edited step");
      }
    });

    test("DELETE of a PUBLISHED revision is rejected (and of APPROVED / SUPERSEDED); a DRAFT can be deleted", async () => {
      const { playbook, revision: published } = await publishedPlaybook(tenantA);
      const approved = await revision(playbook.id, tenantA, 2, "APPROVED");
      const superseded = await revision(playbook.id, tenantA, 3, "SUPERSEDED");
      const draft = await revision(playbook.id, tenantA, 4, "DRAFT");
      for (const r of [published, approved, superseded]) {
        await expect(db.$executeRaw`DELETE FROM playbook_revisions WHERE id = ${r.id}`).rejects.toThrow(/PLAYBOOK_REVISION_IMMUTABLE/);
        expect(await db.playbookRevision.findUnique({ where: { id: r.id } })).not.toBeNull();
      }
      await db.playbookRevision.delete({ where: { id: draft.id } });
      expect(await db.playbookRevision.findUnique({ where: { id: draft.id } })).toBeNull();
    });
  });

  describe("DB constraints: one PUBLISHED revision, and the pointer always matches it", () => {
    test("revisionNumber and version are unique within a playbook", async () => {
      const { playbook } = await publishedPlaybook(tenantA);
      await expect(db.playbookRevision.create({ data: { tenantId: tenantA, playbookId: playbook.id, revisionNumber: 1, version: "other", content: {}, createdBy: "x" } })).rejects.toThrow();
      await expect(db.playbookRevision.create({ data: { tenantId: tenantA, playbookId: playbook.id, revisionNumber: 99, version: "1.0", content: {}, createdBy: "x" } })).rejects.toThrow();
    });

    test("a second PUBLISHED revision for the same playbook is rejected at commit", async () => {
      const { playbook } = await publishedPlaybook(tenantA);
      await expect(revision(playbook.id, tenantA, 2, "PUBLISHED")).rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
    });

    test("the pointer cannot point to a non-published revision or another playbook's revision", async () => {
      const one = await publishedPlaybook(tenantA);
      const two = await publishedPlaybook(tenantA);
      const draft = await revision(one.playbook.id, tenantA, 2, "DRAFT");
      await expect(db.playbook.update({ where: { id: one.playbook.id }, data: { publishedRevisionId: draft.id } })).rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
      // Another playbook's revision: refused (by the 1:1 unique pointer or by the publication check).
      await expect(db.playbook.update({ where: { id: one.playbook.id }, data: { publishedRevisionId: two.revision.id } })).rejects.toThrow();
      expect((await db.playbook.findUniqueOrThrow({ where: { id: one.playbook.id } })).publishedRevisionId).toBe(one.revision.id);
    });

  });

  /**
   * The publish / rollback transaction pattern STEP 3 will use. The publication invariant is a DEFERRED constraint
   * trigger, and Prisma interactive transactions do not surface an error raised at COMMIT. So the last statement in
   * the transaction is SET CONSTRAINTS ALL IMMEDIATE: the deferred check runs inside that statement, Prisma gets the
   * error, and the whole transaction rolls back.
   */
  describe("publish / rollback transaction pattern: deferred check + SET CONSTRAINTS ALL IMMEDIATE", () => {
    type Tx = Prisma.TransactionClient;
    const immediate = (tx: Tx) => tx.$executeRaw`SET CONSTRAINTS ALL IMMEDIATE`;
    /** Everything a partial update could change, read straight from the DB. */
    const state = async (playbookId: string) => ({
      pointer: (await db.playbook.findUniqueOrThrow({ where: { id: playbookId } })).publishedRevisionId,
      revisions: (await db.playbookRevision.findMany({ where: { playbookId }, orderBy: { revisionNumber: "asc" } }))
        .map((r) => ({ id: r.id, status: r.status, publishedBy: r.publishedBy, publishedAt: r.publishedAt, updatedAt: r.updatedAt, content: r.content })),
    });
    /** v1 PUBLISHED + pointer, v2 APPROVED. */
    async function withApprovedV2() {
      const { playbook, revision: v1 } = await publishedPlaybook(tenantA);
      const v2 = await revision(playbook.id, tenantA, 2, "APPROVED");
      return { playbookId: playbook.id, v1, v2 };
    }
    /** The full, valid swap: old -> SUPERSEDED, new -> PUBLISHED, pointer -> new, then the immediate check. */
    const swap = async (tx: Tx, playbookId: string, from: string, to: string) => {
      await tx.playbookRevision.update({ where: { id: from }, data: { status: "SUPERSEDED" } });
      await tx.playbookRevision.update({ where: { id: to }, data: { status: "PUBLISHED", publishedBy: "admin-1", publishedAt: new Date() } });
      await tx.playbook.update({ where: { id: playbookId }, data: { publishedRevisionId: to } });
      await immediate(tx);
    };

    test("publish valid: v2 becomes PUBLISHED, v1 SUPERSEDED, pointer -> v2; v1 content unchanged", async () => {
      const { playbookId, v1, v2 } = await withApprovedV2();
      await db.$transaction((tx) => swap(tx, playbookId, v1.id, v2.id));
      const after = await state(playbookId);
      expect(after.pointer).toBe(v2.id);
      expect(after.revisions.map((r) => r.status)).toEqual(["SUPERSEDED", "PUBLISHED"]);
      expect(after.revisions[0].content).toEqual(v1.content);
    });

    test("publish invalid (status changed, pointer not moved): Prisma gets the error, nothing is written", async () => {
      const { playbookId, v1, v2 } = await withApprovedV2();
      const before = await state(playbookId);
      await expect(db.$transaction(async (tx) => {
        await tx.playbookRevision.update({ where: { id: v1.id }, data: { status: "SUPERSEDED" } });
        await tx.playbookRevision.update({ where: { id: v2.id }, data: { status: "PUBLISHED", publishedBy: "admin-1", publishedAt: new Date() } });
        await immediate(tx);
      })).rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
      expect(await state(playbookId)).toEqual(before);
    });

    test("publish invalid (pointer moved to a revision that is not PUBLISHED): Prisma gets the error, nothing is written", async () => {
      const { playbookId, v2 } = await withApprovedV2();
      const before = await state(playbookId);
      await expect(db.$transaction(async (tx) => {
        await tx.playbook.update({ where: { id: playbookId }, data: { publishedRevisionId: v2.id } });
        await immediate(tx);
      })).rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
      expect(await state(playbookId)).toEqual(before);
    });

    test("rollback valid: back to v1 by pointer and status only; v1 content is byte-identical", async () => {
      const { playbookId, v1, v2 } = await withApprovedV2();
      await db.$transaction((tx) => swap(tx, playbookId, v1.id, v2.id));
      await db.$transaction((tx) => swap(tx, playbookId, v2.id, v1.id));
      const after = await state(playbookId);
      expect(after.pointer).toBe(v1.id);
      expect(after.revisions.map((r) => r.status)).toEqual(["PUBLISHED", "SUPERSEDED"]);
      expect(after.revisions[0].content).toEqual(v1.content);
      expect(after.revisions[1].content).toEqual(v2.content);
    });

    test("rollback invalid (pointer back to v1 but v1 left SUPERSEDED): Prisma gets the error, nothing is written", async () => {
      const { playbookId, v1, v2 } = await withApprovedV2();
      await db.$transaction((tx) => swap(tx, playbookId, v1.id, v2.id));
      const before = await state(playbookId);
      await expect(db.$transaction(async (tx) => {
        await tx.playbookRevision.update({ where: { id: v2.id }, data: { status: "SUPERSEDED" } });
        await tx.playbook.update({ where: { id: playbookId }, data: { publishedRevisionId: v1.id } });
        await immediate(tx);
      })).rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
      expect(await state(playbookId)).toEqual(before);
    });

    test("rollback invalid (two PUBLISHED revisions): Prisma gets the error, nothing is written", async () => {
      const { playbookId, v1, v2 } = await withApprovedV2();
      await db.$transaction((tx) => swap(tx, playbookId, v1.id, v2.id));
      const before = await state(playbookId);
      await expect(db.$transaction(async (tx) => {
        await tx.playbookRevision.update({ where: { id: v1.id }, data: { status: "PUBLISHED" } });
        await tx.playbook.update({ where: { id: playbookId }, data: { publishedRevisionId: v1.id } });
        await immediate(tx);
      })).rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
      expect(await state(playbookId)).toEqual(before);
    });

    test("regression: the failure reaches Prisma as an error and rolls the transaction back (DB state checked, not only the message)", async () => {
      const { playbookId, v1, v2 } = await withApprovedV2();
      const before = await state(playbookId);
      let caught: unknown;
      let reachedAfterCheck = false;
      try {
        await db.$transaction(async (tx) => {
          await tx.playbookRevision.update({ where: { id: v1.id }, data: { status: "SUPERSEDED" } });
          await tx.playbookRevision.update({ where: { id: v2.id }, data: { status: "PUBLISHED" } });
          await immediate(tx);
          reachedAfterCheck = true;
        });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(Error);
      expect(reachedAfterCheck).toBe(false); // the check failed inside the transaction, before any later statement
      expect((caught as Error).message).toMatch(/PLAYBOOK_PUBLICATION_INVALID/);
      expect(await state(playbookId)).toEqual(before);
    });

    test("without SET CONSTRAINTS the DB still rolls back at COMMIT (Prisma may not report it) - so services must use it", async () => {
      const { playbookId, v1, v2 } = await withApprovedV2();
      const before = await state(playbookId);
      await db.$transaction(async (tx) => {
        await tx.playbookRevision.update({ where: { id: v1.id }, data: { status: "SUPERSEDED" } });
        await tx.playbookRevision.update({ where: { id: v2.id }, data: { status: "PUBLISHED" } });
      }).catch(() => undefined); // whatever Prisma reports, the DB must not keep the partial state
      expect(await state(playbookId)).toEqual(before);
    });

    test("STEP 3 feasibility: inside AtomicWorkflow (scope 'playbook') an invalid publish rejects, rolls back and skips after-commit effects", async () => {
      const atomic = new AtomicWorkflow(db);
      const effects: string[] = [];
      const valid = await withApprovedV2();
      await atomic.run("playbook", { tenantId: tenantA }, async () => {
        const tx = atomic.prisma as unknown as Tx;
        await atomic.afterCommit(async () => void effects.push("valid"));
        await swap(tx, valid.playbookId, valid.v1.id, valid.v2.id);
      });
      expect(effects).toEqual(["valid"]);
      expect((await state(valid.playbookId)).pointer).toBe(valid.v2.id);

      const invalid = await withApprovedV2();
      const before = await state(invalid.playbookId);
      await expect(atomic.run("playbook", { tenantId: tenantA }, async () => {
        const tx = atomic.prisma as unknown as Tx;
        await atomic.afterCommit(async () => void effects.push("invalid"));
        await tx.playbookRevision.update({ where: { id: invalid.v2.id }, data: { status: "PUBLISHED" } });
        await immediate(tx);
      })).rejects.toThrow(/PLAYBOOK_PUBLICATION_INVALID/);
      expect(effects).toEqual(["valid"]); // no after-commit effect for the rolled-back publish
      expect(await state(invalid.playbookId)).toEqual(before);
    });
  });

  describe("tenant isolation is unchanged", () => {
    test("a revision cannot be attached to another tenant's playbook", async () => {
      const { playbook } = await publishedPlaybook(tenantA);
      await expect(revision(playbook.id, tenantB, 2, "DRAFT")).rejects.toThrow(/PLAYBOOK_REVISION_TENANT_MISMATCH/);
    });

    test("the playbook repository still scopes reads by tenant", async () => {
      const { playbook } = await publishedPlaybook(tenantA);
      const repo = new PrismaPlaybookRepository(db);
      expect(await repo.findById(playbook.id, tenantA)).not.toBeNull();
      expect(await repo.findById(playbook.id, tenantB)).toBeNull();
      expect((await repo.findAll(tenantB)).some((p) => p.id === playbook.id)).toBe(false);
    });

    test("deleting a playbook that has revisions is refused by the DB, nothing is removed", async () => {
      const { playbook } = await publishedPlaybook(tenantA);
      await expect(new PrismaPlaybookRepository(db).delete(playbook.id, tenantA)).rejects.toThrow();
      expect(await db.playbook.findUnique({ where: { id: playbook.id } })).not.toBeNull();
      expect(await db.playbookStep.count({ where: { playbookId: playbook.id } })).toBe(1);
    });
  });

  describe("existing readers keep working", () => {
    test("repository reads and PlaybookSelector see the same playbooks as the published revision content", async () => {
      const tenants = (await db.playbook.findMany({ where: { tenantId: { notIn: testTenants() } }, select: { tenantId: true }, distinct: ["tenantId"] })).map((t) => t.tenantId);
      const selector = new PlaybookSelector();
      for (const tenantId of tenants) {
        const repo = new PrismaPlaybookRepository(db);
        const playbooks = await repo.findAll(tenantId);
        const revisions = await db.playbookRevision.findMany({ where: { tenantId, status: "PUBLISHED" } });
        const byCode = new Map(revisions.map((r) => [(r.content as { code: string }).code, r.content as Record<string, unknown>]));
        for (const p of playbooks) {
          const c = byCode.get(p.code!)!;
          expect({ name: p.name, version: p.version, status: p.status, steps: p.steps.length }).toEqual({ name: c.name, version: c.version, status: c.playbookStatus, steps: (c.steps as unknown[]).length });
        }
        const expectedTypes = [...byCode.values()]
          .filter((c) => c.playbookStatus === "ACTIVE" && (c.triggerConditions as Record<string, unknown>)?.scope === "INCIDENT" && typeof (c.triggerConditions as Record<string, unknown>)?.incidentType === "string")
          .map((c) => c.code).sort();
        expect(selector.incidentPlaybooks(playbooks).map((p) => p.code).sort()).toEqual(expectedTypes);
      }
    });
  });
});
