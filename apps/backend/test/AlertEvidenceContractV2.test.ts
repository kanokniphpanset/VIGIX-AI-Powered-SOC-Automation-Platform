import fs from "node:fs";
import path from "node:path";
import { buildAlertEvidence } from "../src/domain/investigation/alertEvidence";

const payload = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "wazuh-real", "5712-sshd-bruteforce.json"), "utf8"));
const alert = (over: Record<string, unknown> = {}) => ({
  id: "row-1", externalAlertId: payload.id, siemSource: "wazuh", severity: "medium", rawPayload: payload,
  receivedAt: new Date("2026-10-03T12:23:49.540Z"), createdAt: new Date("2026-10-03T12:23:52.000Z"), ...over,
});

describe("buildAlertEvidence - Evidence Contract v2 flag", () => {
  it("is off by default and leaves structuredData exactly as before", () => {
    const d = buildAlertEvidence(alert(), "inv-1", "system");
    expect(Object.keys(d.structuredData as object).sort()).toEqual(["agent", "alertSeverity", "description", "externalAlertId", "ruleId", "level", "siemSource"].sort());
  });

  it("adds contractV2 additively when switched on, using the true receipt time", () => {
    const off = buildAlertEvidence(alert(), "inv-1", "system").structuredData as Record<string, unknown>;
    const on = buildAlertEvidence(alert(), "inv-1", "system", { contractV2: true }).structuredData as Record<string, any>;
    for (const k of Object.keys(off)) expect(on[k]).toEqual(off[k]);
    expect(on.contractV2.contractVersion).toBe(2);
    expect(on.contractV2.provenance.time.receivedAt).toBe("2026-10-03T12:23:52.000Z");
    expect(on.contractV2.provenance.source.alertRowId).toBe("row-1");
  });

  it("never blocks the evidence row when v2 cannot read the alert", () => {
    const bad = buildAlertEvidence(alert({ rawPayload: { ...payload, rule: { id: "1", level: 3 } } }), "inv-1", "system", { contractV2: true });
    expect((bad.structuredData as Record<string, any>).contractV2).toBeUndefined();
    expect((bad.structuredData as Record<string, any>).contractV2Error).toMatch(/INVALID_WAZUH_PAYLOAD/);
    const noReceipt = buildAlertEvidence(alert({ createdAt: undefined }), "inv-1", "system", { contractV2: true });
    expect((noReceipt.structuredData as Record<string, any>).contractV2Error).toMatch(/createdAt/);
  });

  it("ignores non-Wazuh alerts", () => {
    const d = buildAlertEvidence(alert({ siemSource: "splunk" }), "inv-1", "system", { contractV2: true });
    expect((d.structuredData as Record<string, any>).contractV2).toBeUndefined();
    expect((d.structuredData as Record<string, any>).contractV2Error).toBeUndefined();
  });
});

describe("PrismaInvestigationRepository.recordObservation (observations are auxiliary)", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { Prisma } = require("@prisma/client");
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { PrismaInvestigationRepository } = require("../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma");
  const obs = { sourcePath: "data.srcip", role: "SOURCE", roleBasis: "x", lastKnown: false, provenanceClass: "REAL_TELEMETRY" };
  const repoThrowing = (code: string) =>
    new PrismaInvestigationRepository({ iocObservation: { create: async () => { throw new Prisma.PrismaClientKnownRequestError("boom", { code, clientVersion: "5" }); } } });

  it("treats a duplicate (P2002) as already recorded", async () => {
    await expect(repoThrowing("P2002").recordObservation("ioc", "a", "e", obs, new Date())).resolves.toBeUndefined();
  });

  it("does not break the investigation sync when the migration has not been applied (P2021), and warns once", async () => {
    const warn = jest.spyOn(console, "warn").mockImplementation(() => undefined);
    const repo = repoThrowing("P2021");
    await expect(repo.recordObservation("ioc", "a", "e", obs, new Date())).resolves.toBeUndefined();
    await repo.recordObservation("ioc", "a", "e", obs, new Date());
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it("still surfaces every other database error", async () => {
    await expect(repoThrowing("P2003").recordObservation("ioc", "a", "e", obs, new Date())).rejects.toThrow();
  });
});
