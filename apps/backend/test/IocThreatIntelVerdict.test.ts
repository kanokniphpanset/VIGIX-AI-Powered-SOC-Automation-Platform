import { ListIocsByIncidentUseCase } from "../src/application/incident/use-cases/ListIocsByIncident.usecase";
import { toVerdict } from "../src/infrastructure/database/postgres/repositories/ThreatIntelVerdictReader.prisma";

/**
 * The IOC table shows the Threat Intelligence verdict the AI pipeline already recorded (output contract
 * `threatIntel.indicators`). Display only: getIocs() — also the recommendation context — is returned unchanged.
 */

// Shape recorded by the orchestrator for a real MISP match (E2E 2026-09-26, IP from the APNIC SSH-bruteforce feed).
const RECORDED = {
  ioc: "101.227.203.162",
  iocType: "IPV4",
  status: "SUCCESS",
  verdict: "SUSPICIOUS",
  confidence: 0.7,
  queriedAt: "2026-09-26T17:50:29Z",
  executionId: "exec-1",
  providers: [{ provider: "misp", status: "SUCCESS", source: "LIVE", evidence: [] }],
  evidence: [{ provider: "misp", summary: "Matched MISP attribute of category 'Network activity' in event 2.", reference: "https://localhost:8443/events/view/2" }],
};

const IOCS = [
  { iocType: "IPV4", iocValue: "101.227.203.162", source: "aggregated", reputationScore: null },
  { iocType: "USERNAME", iocValue: "vigixcore", source: "ALERT", reputationScore: null },
];

function useCase(verdicts: unknown[] | Error, incident: unknown = { id: "inc-1" }) {
  return new ListIocsByIncidentUseCase(
    { findById: async () => incident } as never,
    { getIocs: async () => IOCS.map((i) => ({ ...i })) } as never,
    { latestVerdicts: async () => { if (verdicts instanceof Error) throw verdicts; return verdicts.map((v) => toVerdict(v, "exec-1")!).filter(Boolean); } },
  );
}

test("maps a recorded indicator: verdict, confidence, provider, evidence reference", () => {
  expect(toVerdict(RECORDED, null)).toEqual({
    iocType: "IPV4",
    iocValue: "101.227.203.162",
    verdict: "SUSPICIOUS",
    confidence: 0.7,
    providers: [{ provider: "misp", status: "SUCCESS", source: "LIVE" }],
    evidence: [{ provider: "misp", summary: "Matched MISP attribute of category 'Network activity' in event 2.", reference: "https://localhost:8443/events/view/2" }],
    queriedAt: "2026-09-26T17:50:29Z",
    executionId: "exec-1",
  });
  expect(toVerdict({ verdict: "UNKNOWN" }, null)).toBeNull();
});

test("each IOC carries its recorded verdict (type + value match, case-insensitive); others get null", async () => {
  const r = await useCase([{ ...RECORDED, ioc: "101.227.203.162 ", iocType: "ipv4" }]).execute({ incidentId: "inc-1", tenantId: "t1" });
  expect(r.isSuccess).toBe(true);
  const [ip, user] = r.value;
  expect(ip.threatIntel?.verdict).toBe("SUSPICIOUS");
  expect(ip.threatIntel?.evidence[0].reference).toBe("https://localhost:8443/events/view/2");
  expect(user.threatIntel).toBeNull();
  // the IOC fields themselves are exactly what getIocs() returned
  expect({ ...ip, threatIntel: undefined }).toEqual({ ...IOCS[0], threatIntel: undefined });
});

test("no recorded report, or a failing read, still returns the IOCs (verdict null)", async () => {
  for (const verdicts of [[], new Error("db down")]) {
    const r = await useCase(verdicts).execute({ incidentId: "inc-1", tenantId: "t1" });
    expect(r.value.map((i) => i.threatIntel)).toEqual([null, null]);
  }
});

test("tenant check is unchanged", async () => {
  const r = await useCase([], null).execute({ incidentId: "inc-x", tenantId: "t1" });
  expect(r.isFailure).toBe(true);
});
