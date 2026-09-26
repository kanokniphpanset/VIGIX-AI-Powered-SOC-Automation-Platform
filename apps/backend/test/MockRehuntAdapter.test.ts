import * as fs from "node:fs";
import * as path from "node:path";

import { MockRehuntAdapter, DEFAULT_MOCK_ATTACKS_DIR } from "../src/infrastructure/external-services/siem/MockRehuntAdapter";
import { RehuntError, RehuntQuery } from "../src/application/verification/ports/ISiemRehuntPort";
import { extractAlertIocs, REHUNT_IOC_TYPES } from "../src/domain/investigation/alertIocs";

/**
 * Task 9 — MockRehuntAdapter over resources/mock-attacks/**\/rehunt.rounds.
 * Queries are built the way RunRehuntVerificationUseCase builds them: hosts = original alert agent (+ response
 * target when it is a host), rule = original alert rule, iocs = the incident's hunted IOCs. The fixture rounds'
 * `expected` numbers describe a CORRELATED incident (primary + related alerts), so those IOCs are used here.
 */

type Obj = Record<string, any>;
const cases: Obj[] = fs
  .readdirSync(DEFAULT_MOCK_ATTACKS_DIR, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .flatMap((d) => fs.readdirSync(path.join(DEFAULT_MOCK_ATTACKS_DIR, d.name)).filter((f) => /^case-.*\.json$/.test(f)).map((f) => path.join(DEFAULT_MOCK_ATTACKS_DIR, d.name, f)))
  .sort()
  .map((f) => JSON.parse(fs.readFileSync(f, "utf-8")));

const SEARCHABLE = new Set(["ip", "domain", "url", "hash"]);
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

function queryFor(c: Obj, round: number): RehuntQuery {
  const hosts = [c.alert.agent.name];
  const iocs = new Map<string, string>();
  for (const a of [c.alert, ...(c.relatedAlerts ?? [])]) {
    for (const i of extractAlertIocs(a)) if (REHUNT_IOC_TYPES.includes(i.iocType)) iocs.set(i.value, i.iocType);
  }
  for (const i of c.expected.iocs) if (SEARCHABLE.has(i.type)) iocs.set(i.value, i.type);
  const target: string | null = c.response.target;
  if (target) {
    if (IPV4.test(target) || /^[a-f0-9]{32,64}$/i.test(target) || /^https?:\/\//i.test(target)) iocs.set(target, "target");
    else if (!hosts.includes(target)) hosts.push(target);
  }
  return {
    incidentId: c.id,
    responseId: `${c.id}-resp`,
    hosts,
    iocs: [...iocs].map(([value, type]) => ({ type, value })),
    rule: { id: String(c.alert.rule.id), description: c.alert.rule.description },
    timeRange: { start: new Date("2026-09-18T12:00:00Z"), end: new Date("2026-09-18T18:00:00Z") },
    investigationNumber: round,
  };
}

describe("MockRehuntAdapter — fixture rounds", () => {
  const adapter = new MockRehuntAdapter();

  it("loads all 10 cases", async () => {
    expect((await adapter.health()).alertIndices).toBe(10);
    expect(cases).toHaveLength(10);
  });

  const rounds = cases.flatMap((c) => c.rehunt.rounds.map((r: Obj) => [`${c.id} round ${r.round} (${r.scenario})`, c, r] as const));
  it.each(rounds)("%s reproduces the fixture's expected result", async (_n, c, r) => {
    const res = await adapter.rehunt(queryFor(c, r.round));
    expect({
      matchingEvents: res.matchingEvents,
      iocRecurrence: res.iocRecurrence,
      spreadDetected: res.spreadDetected,
      threatContained: res.threatContained,
    }).toEqual({
      matchingEvents: r.expected.matchingEvents,
      iocRecurrence: r.expected.iocRecurrence,
      spreadDetected: r.expected.spreadDetected,
      threatContained: r.expected.threatContained,
    });
    expect(res.source).toBe("MOCK_REHUNT");
    expect(res.index).toContain(`#round-${r.round}`);
    for (const e of res.events) {
      if (e.matchedIoc) expect(e.matchedIocValues!.length).toBeGreaterThan(0);
    }
  });

  it("SPREAD (ATK-06) names the host outside the incident", async () => {
    const atk06 = cases.find((c) => c.id === "ATK-06")!;
    const res = await adapter.rehunt(queryFor(atk06, 1));
    expect(res.affectedHosts.sort()).toEqual(["WEB-01", "WEB-02"]);
    expect(res.spreadDetected).toBe(true);
  });

  it("picks ATK-01 vs ATK-02 (same rule and host) by IOC overlap", async () => {
    const atk01 = cases.find((c) => c.id === "ATK-01")!;
    const atk02 = cases.find((c) => c.id === "ATK-02")!;
    expect((await adapter.rehunt(queryFor(atk01, 1))).index).toContain("case-01-resolved");
    expect((await adapter.rehunt(queryFor(atk02, 1))).index).toContain("case-02-not-resolved");
  });
});

describe("MockRehuntAdapter — failures are errors, never NO_MATCH", () => {
  const atk01 = () => queryFor(cases.find((c) => c.id === "ATK-01")!, 1);

  it.each([
    ["ERROR", "QUERY_FAILED"],
    ["TIMEOUT", "TIMEOUT"],
    ["INDEXER_UNAVAILABLE", "UNREACHABLE"],
  ] as const)("mode %s throws RehuntError %s", async (mode, code) => {
    const adapter = new MockRehuntAdapter(mode);
    await expect(adapter.rehunt(atk01())).rejects.toMatchObject({ code });
    await expect(adapter.rehunt(atk01())).rejects.toBeInstanceOf(RehuntError);
    expect((await adapter.health()).reachable).toBe(false);
  });

  it("a round the fixture does not have is QUERY_FAILED, not a clean result", async () => {
    await expect(new MockRehuntAdapter().rehunt({ ...atk01(), investigationNumber: 2 })).rejects.toMatchObject({ code: "QUERY_FAILED" });
  });

  it("an incident no fixture describes is QUERY_FAILED", async () => {
    await expect(new MockRehuntAdapter().rehunt({ ...atk01(), hosts: ["UNKNOWN-HOST"] })).rejects.toMatchObject({ code: "QUERY_FAILED" });
  });

  it("no IOC and no rule is INSUFFICIENT_CRITERIA", async () => {
    await expect(new MockRehuntAdapter().rehunt({ ...atk01(), iocs: [], rule: undefined })).rejects.toMatchObject({ code: "INSUFFICIENT_CRITERIA" });
  });

  it("missing fixture directory is UNREACHABLE", async () => {
    await expect(new MockRehuntAdapter("FIXTURE", path.join(__dirname, "nope")).rehunt(atk01())).rejects.toMatchObject({ code: "UNREACHABLE" });
  });
});
