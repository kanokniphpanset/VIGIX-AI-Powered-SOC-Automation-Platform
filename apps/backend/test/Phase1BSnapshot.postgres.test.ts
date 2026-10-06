import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { PrismaRecommendationRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { CreateRecommendationData } from "../src/domain/recommendation/repositories/IRecommendationRepository";

// Opt-in only. Never fall back to DATABASE_URL or load a runtime .env.
const url = process.env.PHASE1B_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
suite("Phase 1B — real PostgreSQL immutable snapshots", () => {
  let db: PrismaClient;
  let repo: PrismaRecommendationRepository;
  let tenantId: string;
  let incidentId: string;
  let investigationId: string;
  const queries: string[] = [];
  const input = (number: number, version = "1"): CreateRecommendationData => ({
    tenantId, incidentId, investigationNumber: 1, recommendationNumber: number,
    status: "VALIDATED", summary: `generation ${number}`, createdBy: "test-agent", steps: [],
    snapshot: { playbookCode: "PB-TEST", playbookVersion: version, procedureCode: "PROC-TEST",
      procedureVersion: version, procedureContent: { instructions: [`version ${version}`] }, policyResult: { approvalRequired: true } },
  });
  beforeAll(async () => {
    if (!url || !/^vigix_phase1b_test_[a-z0-9_]+$/.test(new URL(url).pathname.slice(1))) {
      throw new Error("Dedicated Phase 1B database required; runtime/evaluation targets are forbidden");
    }
    const client = new PrismaClient({ datasources: { db: { url } }, log: [{ emit: "event", level: "query" }] });
    client.$on("query", event => queries.push(event.query));
    db = client;
    repo = new PrismaRecommendationRepository(db);
    tenantId = randomUUID();
    await db.tenant.create({ data: { id: tenantId, name: "Phase1B isolated test" } });
    const alert = await db.alert.create({ data: { tenantId, siemSource: "test", externalAlertId: randomUUID(), rawPayload: {}, severity: "medium", receivedAt: new Date() } });
    const incident = await db.incident.create({ data: { tenantId, alertId: alert.id, title: "Phase1B isolated" } });
    incidentId = incident.id;
    investigationId = (await db.investigation.create({ data: { incidentId, investigationNumber: 1, createdBy: "test" } })).id;
  });
  afterAll(async () => { if (db) await db.$disconnect(); }); // Preserve fixtures; no cleanup DELETE/reset.

  test("first generation creates exactly one referenced snapshot", async () => {
    const recommendation = await repo.create(input(1));
    const snapshots = await db.playbookSnapshot.findMany({ where: { incidentId } });
    expect(snapshots).toHaveLength(1);
    expect(recommendation.snapshotId).toBe(snapshots[0].id);
    expect(snapshots[0]).toMatchObject({ investigationId, investigationNumber: 1, playbookVersion: "1" });
  });
  test("regeneration preserves old content and references; same cycle coexists", async () => {
    const first = (await repo.findAllByIncident(incidentId, tenantId))[0];
    const before = await db.playbookSnapshot.findUniqueOrThrow({ where: { id: first.snapshotId! } });
    const second = await repo.create(input(2, "2"));
    expect(second.snapshotId).not.toBe(first.snapshotId);
    expect(await db.playbookSnapshot.findUniqueOrThrow({ where: { id: first.snapshotId! } })).toEqual(before);
    expect((await repo.findById(first.id, tenantId))!.snapshotId).toBe(before.id);
    expect((await repo.findById(second.id, tenantId))!.snapshotId).toBe(second.snapshotId);
    expect(await db.playbookSnapshot.findUniqueOrThrow({ where: { id: second.snapshotId! } })).toMatchObject({ playbookVersion: "2", procedureContent: input(2, "2").snapshot!.procedureContent });
    expect(await db.playbookSnapshot.count({ where: { incidentId, investigationNumber: 1 } })).toBe(2);
  });
  test("identical content still creates distinct immutable artifacts", async () => {
    const a = await repo.create(input(3, "same"));
    const b = await repo.create(input(4, "same"));
    expect(a.snapshotId).not.toBe(b.snapshotId);
    const snapshots = await db.playbookSnapshot.findMany({ where: { id: { in: [a.snapshotId!, b.snapshotId!] } } });
    expect(snapshots[0].procedureContent).toEqual(snapshots[1].procedureContent);
  });
  test("concurrent generation allocates separate numbers and keeps references correct", async () => {
    const [a, b] = await Promise.all([repo.create(input(5, "concurrent-A")), repo.create(input(5, "concurrent-B"))]);
    expect(new Set([a.recommendationNumber, b.recommendationNumber]).size).toBe(2);
    expect(a.snapshotId).not.toBe(b.snapshotId);
    for (const rec of [a, b]) {
      const snap = await db.playbookSnapshot.findUniqueOrThrow({ where: { id: rec.snapshotId! } });
      expect(snap.code).toBe(`SNAP-${incidentId}-1-${rec.recommendationNumber}`);
    }
    const newer = a.recommendationNumber > b.recommendationNumber ? a : b;
    const older = newer === a ? b : a;
    await repo.supersedePrevious(incidentId, tenantId, newer.id);
    await repo.supersedePrevious(incidentId, tenantId, older.id);
    expect((await repo.findById(newer.id, tenantId))!.status).toBe("VALIDATED");
  });
  test("failed recommendation insertion rolls back its new snapshot", async () => {
    const before = await db.playbookSnapshot.count({ where: { incidentId } });
    await expect(repo.create({ ...input(7), summary: null as unknown as string })).rejects.toThrow();
    expect(await db.playbookSnapshot.count({ where: { incidentId } })).toBe(before);
  });
  test("repository regeneration never updates/upserts/deletes snapshot content", async () => {
    const update = jest.spyOn(db.playbookSnapshot, "update");
    const upsert = jest.spyOn(db.playbookSnapshot, "upsert");
    const remove = jest.spyOn(db.playbookSnapshot, "delete");
    // Interactive transaction delegates are distinct; inspect the actual SQL as well.
    const allBefore = await db.playbookSnapshot.findMany({ where: { incidentId }, orderBy: { id: "asc" } });
    const queryStart = queries.length;
    await repo.create(input(7, "final"));
    const allAfter = await db.playbookSnapshot.findMany({ where: { id: { in: allBefore.map(s => s.id) } }, orderBy: { id: "asc" } });
    expect(allAfter).toEqual(allBefore);
    expect(queries.slice(queryStart).filter(q => /(?:UPDATE|DELETE FROM)\s+"(?:public"\.")?playbook_snapshots"/i.test(q))).toEqual([]);
    expect(update).not.toHaveBeenCalled(); expect(upsert).not.toHaveBeenCalled(); expect(remove).not.toHaveBeenCalled();
    jest.restoreAllMocks();
  });
  test("legacy shared snapshots and old codes remain readable after new generation", async () => {
    const alert = await db.alert.create({ data: { tenantId, siemSource: "test", externalAlertId: randomUUID(), rawPayload: {}, severity: "medium", receivedAt: new Date() } });
    const legacyIncident = await db.incident.create({ data: { tenantId, alertId: alert.id, title: "Legacy snapshot fixture" } });
    const investigation = await db.investigation.create({ data: { incidentId: legacyIncident.id, investigationNumber: 1, createdBy: "legacy" } });
    const legacy = await db.playbookSnapshot.create({ data: {
      tenantId, incidentId: legacyIncident.id, investigationId: investigation.id, investigationNumber: 1,
      code: `SNAP-${legacyIncident.id}-1`, playbookCode: "PB-LEGACY", playbookVersion: "legacy",
      procedureCode: "PROC-LEGACY", procedureVersion: "legacy", procedureContent: { historical: true }, policyResult: {} } });
    const oldIds: string[] = [];
    for (const number of [1, 2]) {
      const rec = await db.recommendation.create({ data: { tenantId, incidentId: legacyIncident.id,
        investigationId: investigation.id, investigationNumber: 1, recommendationNumber: number,
        snapshotId: legacy.id, summary: "legacy", createdBy: "legacy" } });
      oldIds.push(rec.id);
    }
    const next = await repo.create({ ...input(3, "new"), incidentId: legacyIncident.id });
    expect(next.snapshotId).not.toBe(legacy.id);
    expect(await db.playbookSnapshot.findUniqueOrThrow({ where: { id: legacy.id } })).toEqual(legacy);
    for (const id of oldIds) expect((await repo.findById(id, tenantId))!.snapshotId).toBe(legacy.id);
  });
});
