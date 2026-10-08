import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { PrismaInvestigationRepository } from "../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma";

/**
 * Phase 2C against a real PostgreSQL: ioc_observations written by the investigation sync when EVIDENCE_CONTRACT_V2 is on.
 * Needs a dedicated scratch database that has had `prisma migrate deploy` run (never a runtime database):
 *   IOC_OBSERVATIONS_TEST_DATABASE_URL=postgresql://.../soar_p2c_fresh npx jest test/IocObservations.postgres.test.ts
 */
const url = process.env.IOC_OBSERVATIONS_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
jest.setTimeout(30000);
const fixture = (name: string) => JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "wazuh-real", name), "utf8"));

suite("IOC observations (Evidence Contract v2), real PostgreSQL", () => {
  let db: PrismaClient;
  let repo: PrismaInvestigationRepository;
  let tenantId: string;
  const priorFlag = process.env.EVIDENCE_CONTRACT_V2;
  let seq = 0;

  beforeAll(async () => {
    if (!url || !/^(soar_p2c_(fresh|clone)|vigix_p2c_test_[a-z0-9_]+)$/.test(new URL(url).pathname.slice(1))) {
      throw new Error("Explicit dedicated scratch DB required (soar_p2c_fresh | soar_p2c_clone | vigix_p2c_test_*)");
    }
    db = new PrismaClient({ datasources: { db: { url } } });
    repo = new PrismaInvestigationRepository(db);
    tenantId = (await db.tenant.create({ data: { name: `p2c ${randomUUID()}` } })).id;
  });

  afterAll(async () => {
    if (priorFlag === undefined) delete process.env.EVIDENCE_CONTRACT_V2; else process.env.EVIDENCE_CONTRACT_V2 = priorFlag;
    await db?.$disconnect();
  });

  async function incidentFor(fixtureName: string) {
    const payload = fixture(fixtureName);
    const alert = await db.alert.create({
      data: { tenantId, externalAlertId: `${payload.id.split(".")[0]}.${++seq}${Date.now()}`, siemSource: "wazuh", rawPayload: payload, severity: "high", status: "received", receivedAt: new Date() },
    });
    const incident = await db.incident.create({ data: { tenantId, alertId: alert.id, title: "p2c", priority: "high", status: "open" } });
    await db.incidentAlert.create({ data: { incidentId: incident.id, alertId: alert.id } });
    return { payload, alert, incident };
  }
  const firstInvestigation = (incidentId: string) => db.investigation.findFirstOrThrow({ where: { incidentId, investigationNumber: 1 } });

  it("flag off: IOCs exactly as before and no observations", async () => {
    process.env.EVIDENCE_CONTRACT_V2 = "false";
    const { incident } = await incidentFor("5712-sshd-bruteforce.json");
    await repo.syncIncident(incident.id, tenantId);
    const inv = await firstInvestigation(incident.id);
    expect((await db.threatIntelIoc.findMany({ where: { investigationId: inv.id } })).length).toBe(2);
    expect(await repo.listIocObservations(inv.id)).toEqual([]);
  });

  it("flag on: every IOC carries its Wazuh path, role and provenance; a second sync adds nothing", async () => {
    process.env.EVIDENCE_CONTRACT_V2 = "true";
    const { incident, alert } = await incidentFor("5712-sshd-bruteforce.json");
    await repo.syncIncident(incident.id, tenantId);
    await repo.syncIncident(incident.id, tenantId);
    const inv = await firstInvestigation(incident.id);
    const obs = await repo.listIocObservations(inv.id);
    expect(obs.map((o) => [o.sourcePath, o.role, o.provenanceClass]).sort()).toEqual([
      ["data.srcip", "SOURCE", "REAL_TELEMETRY"],
      ["data.srcuser", "ACTOR", "REAL_TELEMETRY"],
    ]);
    expect(obs.every((o) => o.alertId === alert.id && o.evidenceId)).toBe(true);
    const ioc = await db.threatIntelIoc.findUniqueOrThrow({ where: { id: obs.find((o) => o.sourcePath === "data.srcip")!.iocId } });
    expect([ioc.iocType, ioc.iocValue]).toEqual(["IPV4", "172.19.0.3"]);
  });

  it("flag on: FIM alerts now produce IOCs (the legacy extractor found none) and a deleted file is lastKnown", async () => {
    process.env.EVIDENCE_CONTRACT_V2 = "true";
    const { incident } = await incidentFor("553-fim-deleted.json");
    await repo.syncIncident(incident.id, tenantId);
    const inv = await firstInvestigation(incident.id);
    const obs = await repo.listIocObservations(inv.id);
    expect(obs.length).toBe(4);
    expect(obs.every((o) => o.lastKnown && o.sourcePath.startsWith("syscheck."))).toBe(true);
  });

  it("the reporting host keeps the ENDPOINT_SELF role instead of looking like an attacker", async () => {
    process.env.EVIDENCE_CONTRACT_V2 = "true";
    const { incident, payload } = await incidentFor("100320-harness-c2-beacon.json");
    await repo.syncIncident(incident.id, tenantId);
    const inv = await firstInvestigation(incident.id);
    const obs = await repo.listIocObservations(inv.id);
    const self = await db.threatIntelIoc.findFirstOrThrow({ where: { investigationId: inv.id, iocValue: payload.agent.ip } });
    expect(obs.find((o) => o.iocId === self.id)?.role).toBe("ENDPOINT_SELF");
    expect(obs.find((o) => o.sourcePath === "data.dstip")?.role).toBe("DESTINATION");
    expect(obs.every((o) => o.provenanceClass === "HARNESS_GENERATED")).toBe(true);
  });

  it("the database itself rejects an unknown role, a blank path, an orphan and a duplicate", async () => {
    process.env.EVIDENCE_CONTRACT_V2 = "true";
    const { incident, alert } = await incidentFor("5712-sshd-bruteforce.json");
    await repo.syncIncident(incident.id, tenantId);
    const inv = await firstInvestigation(incident.id);
    const o = (await repo.listIocObservations(inv.id))[0];
    const base = { iocId: o.iocId, alertId: alert.id, provenanceClass: "REAL_TELEMETRY", observedAt: new Date() };
    await expect(db.iocObservation.create({ data: { ...base, sourcePath: "data.x", role: "ATTACKER" } })).rejects.toThrow();
    await expect(db.iocObservation.create({ data: { ...base, sourcePath: "   ", role: "SOURCE" } })).rejects.toThrow();
    await expect(db.iocObservation.create({ data: { iocId: o.iocId, sourcePath: "data.x", role: "SOURCE", provenanceClass: "REAL_TELEMETRY", observedAt: new Date() } })).rejects.toThrow();
    await expect(db.iocObservation.create({ data: { ...base, provenanceClass: "FAKE", sourcePath: "data.x", role: "SOURCE" } })).rejects.toThrow();
    await expect(db.iocObservation.create({ data: { iocId: o.iocId, alertId: o.alertId, evidenceId: o.evidenceId, sourcePath: o.sourcePath, role: "SOURCE", provenanceClass: "REAL_TELEMETRY", observedAt: new Date() } })).rejects.toThrow();
  });

  it("deleting an IOC removes its observations; the alert and evidence survive", async () => {
    process.env.EVIDENCE_CONTRACT_V2 = "true";
    const { incident, alert } = await incidentFor("5712-sshd-bruteforce.json");
    await repo.syncIncident(incident.id, tenantId);
    const inv = await firstInvestigation(incident.id);
    const obs = await repo.listIocObservations(inv.id);
    await db.evidenceIoc.deleteMany({ where: { iocId: obs[0].iocId } });
    await db.threatIntelIoc.delete({ where: { id: obs[0].iocId } });
    expect((await repo.listIocObservations(inv.id)).length).toBe(obs.length - 1);
    expect(await db.alert.findUnique({ where: { id: alert.id } })).not.toBeNull();
  });
});
