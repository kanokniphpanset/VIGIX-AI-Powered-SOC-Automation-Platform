import { PrismaClient } from "@prisma/client";
import { randomUUID } from "node:crypto";
import { AtomicWorkflow } from "../src/infrastructure/database/postgres/AtomicWorkflow";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PrismaGenerationPlaybookCatalogReader } from "../src/infrastructure/database/postgres/repositories/GenerationPlaybookCatalogReader.prisma";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaPlaybookRevisionRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRevisionRepository.prisma";
import { PrismaRecommendationRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { PublishPlaybookRevisionUseCase } from "../src/application/playbook/use-cases/PublishPlaybookRevision.usecase";
import { RollbackPlaybookRevisionUseCase } from "../src/application/playbook/use-cases/RollbackPlaybookRevision.usecase";
import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { PlaybookSelector } from "../src/application/recommendation/services/PlaybookSelector";
import { CreateRecommendationData } from "../src/domain/recommendation/repositories/IRecommendationRepository";
import { hashRevisionContent, PlaybookProvenanceError, PlaybookRevisionProvenance } from "../src/domain/playbook/PlaybookRevisionProvenance";
import { Result } from "../src/shared/result/Result";
import { publishedFixture } from "./helpers/hc1Provenance";

// No dotenv, no DATABASE_URL fallback, no cleanup/reset. Fixtures remain in a dedicated test database.
const url = process.env.HC1_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
jest.setTimeout(60000);
suite("HC-1 exact provenance — PostgreSQL", () => {
  let db: PrismaClient;
  let atomic: AtomicWorkflow;
  let repo: PrismaRecommendationRepository;
  let audit: AuditLogger;
  let reader: PrismaGenerationPlaybookCatalogReader;
  beforeAll(async () => {
    if (!url || !/^vigix_hc1_test_[a-z0-9_]+$/.test(new URL(url).pathname.slice(1))) throw new Error("Dedicated HC-1 test database required");
    db = new PrismaClient({ datasources: { db: { url } } });
    atomic = new AtomicWorkflow(db); repo = new PrismaRecommendationRepository(atomic.prisma);
    audit = new AuditLogger(atomic.prisma); reader = new PrismaGenerationPlaybookCatalogReader(atomic.prisma);
  });
  afterAll(async () => db?.$disconnect());
  async function fixture(investigation = true) {
    const tenant = await db.tenant.create({ data: { name: "HC1 isolated" } });
    const book = await publishedFixture(db, tenant.id);
    const alert = await db.alert.create({ data: { tenantId: tenant.id, siemSource: "hc1-test", externalAlertId: randomUUID(), severity: "medium", rawPayload: {}, receivedAt: new Date() } });
    const incident = await db.incident.create({ data: { tenantId: tenant.id, alertId: alert.id, title: "HC1 test" } });
    if (investigation) await db.investigation.create({ data: { incidentId: incident.id, investigationNumber: 1, createdBy: "hc1-human" } });
    const catalog = await reader.read(tenant.id);
    const selected = new PlaybookSelector().select(catalog.playbooks, ["T1110"])!;
    const pin = catalog.pinSelected(selected.code);
    const input: CreateRecommendationData = { tenantId: tenant.id, incidentId: incident.id, investigationNumber: 1, recommendationNumber: 1,
      status: "VALIDATED", summary: "HC1", createdBy: "test-agent", steps: [], provenance: pin,
      snapshot: { playbookCode: book.code, playbookVersion: pin.version, procedureCode: "P", procedureVersion: "1", procedureContent: { strategy: selected.strategy, runbooks: [] }, policyResult: { approvalRequired: true } } };
    return { tenant, book, incident, catalog, pin, input };
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>;
  async function state(f: Fixture) {
    return {
      snapshots: await db.playbookSnapshot.findMany({ where: { incidentId: f.incident.id }, orderBy: { id: "asc" } }),
      recommendations: await db.recommendation.findMany({ where: { incidentId: f.incident.id }, include: { steps: true }, orderBy: { id: "asc" } }),
      audits: await db.auditLog.findMany({ where: { tenantId: f.tenant.id, action: "RECOMMENDATION_GENERATED" }, orderBy: { id: "asc" } }),
    };
  }
  function generation(f: Fixture, afterPin: () => Promise<void> = async () => {}, pin: PlaybookRevisionProvenance | null = f.pin, recorder = audit) {
    return new GenerateRecommendationUseCase(
      { buildForGeneration: async () => Result.ok({ context: { investigationNumber: 1 }, provenance: pin }) } as never,
      { generate: async () => { await afterPin(); return {}; } }, "hc1-test-agent",
      { validate: async () => ({ status: "VALIDATED", summary: "HC1", steps: [], snapshot: f.input.snapshot, violations: [] }) } as never,
      repo, recorder, atomic);
  }
  async function publish(f: Fixture) {
    const content = { ...f.book.content, name: "Revision B", version: "2.0", steps: [{ stepOrder: 2, title: "second", description: null }, { stepOrder: 1, title: "first", description: null }] };
    const b = await db.playbookRevision.create({ data: { tenantId: f.tenant.id, playbookId: f.book.playbook.id, revisionNumber: 2, version: "2.0", status: "DRAFT", content, createdBy: "hc1-human" } });
    const useCase = atomic.wrap(new PublishPlaybookRevisionUseCase(new PrismaPlaybookRevisionRepository(atomic.prisma), audit), "playbook");
    expect((await useCase.execute({ tenantId: f.tenant.id, id: f.book.playbook.id, revisionId: b.id, actor: { id: "soc", role: "SOC", principalType: "HUMAN" } })).isSuccess).toBe(true);
    return b;
  }
  async function expectTuple(snapshotId: string, pin: PlaybookRevisionProvenance) {
    const s = await db.playbookSnapshot.findUniqueOrThrow({ where: { id: snapshotId } });
    expect(s).toMatchObject({ tenantId: pin.tenantId, playbookId: pin.playbookId, playbookRevisionId: pin.revisionId, playbookVersion: pin.version, contentHash: pin.contentHash, frozenRevisionContent: pin.content });
    expect(s.contentHash).toBe(hashRevisionContent(s.frozenRevisionContent));
    expect(JSON.stringify(s.procedureContent)).not.toContain("provenance");
    return s;
  }
  test("HC1-01 selected published revision pins and persists exact tuple", async () => {
    const f = await fixture(); const result = await generation(f).execute(f.input);
    expect(result.isSuccess).toBe(true);
    const snapshot = await expectTuple(result.value.snapshotId!, f.pin);
    expect(snapshot.procedureContent).toEqual(f.input.snapshot!.procedureContent);
    expect(snapshot.policyResult).toEqual(f.input.snapshot!.policyResult);
    expect((await state(f)).audits).toHaveLength(1);
  });
  test("HC1-02 committed publish on another connection during generation preserves A", async () => {
    const f = await fixture(); const result = await generation(f, async () => { await publish(f); }).execute(f.input);
    expect(result.isSuccess).toBe(true); await expectTuple(result.value.snapshotId!, f.pin);
    expect((await db.playbookRevision.findUniqueOrThrow({ where: { id: f.pin.revisionId } })).status).toBe("SUPERSEDED");
  });
  test("HC1-03 rollback during generation preserves the selected newer revision", async () => {
    const f = await fixture(); await publish(f);
    const selected = (await reader.read(f.tenant.id)).pinSelected(f.book.code);
    f.input.snapshot!.playbookVersion = selected.version;
    const result = await generation(f, async () => {
      const rollback = atomic.wrap(new RollbackPlaybookRevisionUseCase(new PrismaPlaybookRevisionRepository(atomic.prisma), audit), "playbook");
      expect((await rollback.execute({ tenantId: f.tenant.id, id: f.book.playbook.id, revisionId: f.pin.revisionId, actor: { id: "ir", role: "IR_TEAM", principalType: "HUMAN" } })).isSuccess).toBe(true);
    }, selected).execute(f.input);
    expect(result.isSuccess).toBe(true); await expectTuple(result.value.snapshotId!, selected);
  });
  test.each(["revisionId", "playbookId", "version", "content", "contentHash"] as const)("HC1-04 mismatched %s aborts without partial state", async field => {
    const f = await fixture(); await repo.create(f.input); const before = await state(f);
    const pin = { ...f.pin, [field]: field === "content" ? { altered: true } : "wrong" };
    const result = await generation(f, undefined, pin).execute(f.input);
    expect(result.isFailure).toBe(true);
    expect(result.error).toBe(field === "revisionId" ? "PLAYBOOK_PROVENANCE_NOT_FOUND" : "PLAYBOOK_PROVENANCE_MISMATCH");
    expect(await state(f)).toEqual(before);
  });
  test("HC1-05 tenant mismatch / foreign revision ID reject without foreign lookup or changes", async () => {
    const a = await fixture(), b = await fixture(); const beforeA = await state(a), beforeB = await state(b);
    expect((await generation(a, undefined, b.pin).execute(a.input)).error).toBe("PLAYBOOK_PROVENANCE_TENANT_MISMATCH");
    expect((await generation(a, undefined, { ...b.pin, tenantId: a.tenant.id }).execute(a.input)).error).toBe("PLAYBOOK_PROVENANCE_NOT_FOUND");
    expect(await state(a)).toEqual(beforeA); expect(await state(b)).toEqual(beforeB);
    expect((await reader.read(a.tenant.id)).playbooks.every(p => p.tenantId === a.tenant.id)).toBe(true);
  });
  test("HC1-06 audit failure rolls back snapshot, recommendation, steps and supersession", async () => {
    const f = await fixture(); await repo.create(f.input); const before = await state(f);
    const failure = { record: async () => { throw new Error("HC1 injected audit failure"); } } as unknown as AuditLogger;
    await expect(generation(f, undefined, f.pin, failure).execute(f.input)).rejects.toThrow("HC1 injected audit failure");
    expect(await state(f)).toEqual(before);
  });
  test("HC1-06 step insert failure rolls back the new snapshot and recommendation", async () => {
    const f = await fixture(); const before = await state(f);
    await expect(repo.create({ ...f.input, steps: [{ stepOrder: 1, title: "bad", actionId: randomUUID(), reason: "test", evidence: [], instructions: [], requiresApproval: false } as never] })).rejects.toThrow();
    expect(await state(f)).toEqual(before);
  });
  test("HC1-08 ordinary and generation catalog selection have parity", async () => {
    const f = await fixture(); const ordinary = await new PrismaPlaybookRepository(db).findAll(f.tenant.id);
    const selector = new PlaybookSelector();
    expect(selector.select(f.catalog.playbooks, ["T1110.001"], ["T1110.001"])).toEqual(selector.select(ordinary, ["T1110.001"], ["T1110.001"]));
    expect(selector.selectByType(f.catalog.playbooks, f.book.code)).toEqual(selector.selectByType(ordinary, f.book.code));
  });
  test("HC1-09 legacy snapshots remain NULL and unchanged after new generation", async () => {
    const f = await fixture();
    const inv = await db.investigation.findFirstOrThrow({ where: { incidentId: f.incident.id } });
    const old = await db.playbookSnapshot.create({ data: { ...f.input.snapshot! as never as Record<string, never>, tenantId: f.tenant.id, incidentId: f.incident.id, investigationId: inv.id, investigationNumber: 1, code: randomUUID(), playbookCode: "legacy", playbookVersion: "old", procedureCode: "P", procedureVersion: "1", procedureContent: {}, policyResult: {} } });
    await generation(f).execute(f.input);
    expect(await db.playbookSnapshot.findUniqueOrThrow({ where: { id: old.id } })).toEqual(old);
    expect(old.playbookRevisionId).toBeNull(); expect(old.contentHash).toBeNull();
  });
  test("HC1-12 missing Investigation, Snapshot or pin cannot produce incomplete recommendations", async () => {
    const missing = await fixture(false);
    expect((await generation(missing).execute(missing.input)).error).toBe("RECOMMENDATION_INVESTIGATION_REQUIRED");
    expect((await state(missing)).recommendations).toHaveLength(0);
    const f = await fixture(); const before = await state(f);
    for (const input of [{ ...f.input, snapshot: null }, { ...f.input, provenance: null }])
      await expect(repo.create(input)).rejects.toMatchObject({ code: "PLAYBOOK_PROVENANCE_INVALID" });
    expect(await state(f)).toEqual(before);
  });
  test("HC1-13 published and superseded revision content/version stay immutable", async () => {
    const f = await fixture();
    await expect(db.playbookRevision.update({ where: { id: f.pin.revisionId }, data: { content: {} } })).rejects.toThrow();
    await publish(f);
    await expect(db.playbookRevision.update({ where: { id: f.pin.revisionId }, data: { version: "tampered" } })).rejects.toThrow();
    expect((await db.playbookRevision.findUniqueOrThrow({ where: { id: f.pin.revisionId } })).content).toEqual(f.pin.content);
  });
});
