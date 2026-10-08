import { RehuntCoverage, RehuntEvent } from "../src/application/verification/ports/ISiemRehuntPort";
import { classifyRehunt, ClassifyInput, correlationReasons, GENERIC_RULE_GROUPS } from "../src/application/verification/services/classifyRehunt";

/**
 * Phase 2D semantics. The three rules under test:
 *   same IOC != spread · file deleted != recurrence · no matching alert != contained
 * Event shapes mirror what the live Indexer returned for the real cases (ld.so.preload hash, 172.19.0.5, EICAR deletion).
 */
const completeCoverage: RehuntCoverage = {
  sources: { alerts: "AVAILABLE", archives: "NOT_AVAILABLE" }, indexRange: { min: "2026-09-29T00:00:00Z", max: "2026-10-08T00:00:00Z" },
  windowCoveredByIndex: true, agents: [{ name: "attack-endpoint", status: "ACTIVE_THROUGHOUT", nonActiveSnapshots: 0, lastSnapshotAt: null }],
  complete: true, gaps: [], limitations: ["archives are not indexed"],
};
const incompleteCoverage: RehuntCoverage = { ...completeCoverage, complete: false, gaps: ["agent attack-endpoint was not active in 2 status snapshot(s) around the window"] };

const ev = (over: Partial<RehuntEvent> = {}): RehuntEvent => ({
  id: "doc", timestamp: "2026-10-03T12:30:00.000Z", host: "attack-endpoint", agentId: "009", ruleId: "5710", ruleLevel: 5, ruleDescription: "d",
  matchedIoc: true, matchedIocValues: ["172.19.0.3"], ruleGroups: ["syslog", "sshd", "authentication_failures"], ...over,
});
const base = (over: Partial<ClassifyInput> = {}): ClassifyInput => ({
  query: { hosts: ["attack-endpoint"], agentIds: ["009"], rule: { id: "5712", groups: ["syslog", "sshd", "authentication_failures"] } },
  events: [], totalMatched: 0, complete: true, skippedIocTypes: [], coverage: completeCoverage, ...over,
});
const classify = (events: RehuntEvent[], over: Partial<ClassifyInput> = {}) => classifyRehunt(base({ events, totalMatched: events.length, ...over }));

describe("same IOC != spread", () => {
  it("an IOC value seen on another agent, with nothing tying it to the incident, is UNCORROBORATED_MATCH - not spread", () => {
    // live case: IP 172.19.0.5 seen on vigix-lab-agent (rules 5710/5503) while the incident was a FIM/C2 one on attack-endpoint
    const r = classify(
      [ev({ host: "vigix-lab-agent", agentId: "004", ruleId: "100320", ruleGroups: ["vigix_eval", "c2"] })],
      { query: { hosts: ["attack-endpoint"], agentIds: ["009"], rule: { id: "100340", groups: ["vigix_eval", "exfiltration"] } } }
    );
    expect(r.classification).toBe("UNCORROBORATED_MATCH");
    expect(r.matchedHosts).toEqual([]);
    expect(r.events[0].correlation).toEqual({ corroborated: false, reasons: [] });
  });

  it("the same value on another agent IS spread when the same detection fired there", () => {
    const r = classify([ev({ host: "vigix-lab-agent", agentId: "004", ruleId: "5712" })]);
    expect(r.classification).toBe("NEW_SCOPE_ACTIVITY");
    expect(r.matchedHosts).toEqual(["vigix-lab-agent"]);
    expect(r.correlationReasons.SAME_RULE).toBe(1);
  });

  it("or when the same non-generic rule group fired (same kind of activity)", () => {
    const r = classify([ev({ host: "other", agentId: "010", ruleId: "5763", ruleGroups: ["syslog", "sshd", "authentication_failures"] })]);
    expect(r.classification).toBe("NEW_SCOPE_ACTIVITY");
    expect(r.correlationReasons.SHARED_RULE_GROUP).toBe(1);
  });

  it("a generic log-source group never corroborates", () => {
    for (const g of GENERIC_RULE_GROUPS) {
      const r = classify([ev({ host: "other", agentId: "010", ruleId: "9", ruleGroups: [g] })], { query: { hosts: ["attack-endpoint"], rule: { id: "5712", groups: [g] } } });
      expect({ g, c: r.classification }).toEqual({ g, c: "UNCORROBORATED_MATCH" });
    }
  });

  it("the same process guid corroborates across agents", () => {
    const e = ev({ host: "other", agentId: "010", ruleId: "92027", ruleGroups: ["sysmon"], processGuid: "{AB-1}" });
    const r = classify([e], { query: { hosts: ["attack-endpoint"], rule: { id: "5712" }, correlation: { processGuids: ["{ab-1}"] } } });
    expect(r.classification).toBe("NEW_SCOPE_ACTIVITY");
    expect(r.correlationReasons).toEqual({ SAME_PROCESS_GUID: 1 });
  });

  it("the same file path corroborates, but only when the file was added or modified", () => {
    const q = { hosts: ["attack-endpoint"], rule: { id: "100301" }, correlation: { filePaths: ["/tmp/x"] } };
    const added = classify([ev({ host: "other", agentId: "010", ruleId: "554", ruleGroups: ["syscheck"], filePath: "/tmp/x", fileOperation: "added" })], { query: q });
    expect(added.classification).toBe("NEW_SCOPE_ACTIVITY");
    const deleted = classify([ev({ host: "other", agentId: "010", ruleId: "553", ruleGroups: ["syscheck"], filePath: "/tmp/x", fileOperation: "deleted" })], { query: q });
    expect(deleted.classification).toBe("NO_MATCH_COVERED");
  });

  it("an agent is in scope by id even when its name changed, and by name when the id is unknown", () => {
    expect(classify([ev({ host: "renamed", agentId: "009", ruleId: "5712" })]).classification).toBe("IN_SCOPE_ACTIVITY");
    expect(classify([ev({ host: "ATTACK-ENDPOINT", agentId: null, ruleId: "5712" })], { query: { hosts: ["attack-endpoint"], rule: { id: "5712" } } }).classification).toBe("IN_SCOPE_ACTIVITY");
  });

  it("corroborated activity on the original agent is IN_SCOPE_ACTIVITY (recurrence, not spread)", () => {
    const r = classify([ev({ ruleId: "5712" })]);
    expect(r.classification).toBe("IN_SCOPE_ACTIVITY");
    expect(r.matchedHosts).toEqual(["attack-endpoint"]);
  });

  it("new-scope activity wins over in-scope activity", () => {
    expect(classify([ev({ ruleId: "5712" }), ev({ id: "d2", host: "other", agentId: "010", ruleId: "5712" })]).classification).toBe("NEW_SCOPE_ACTIVITY");
  });

  it("reasons are stated per event and an IOC match is required for any", () => {
    expect(correlationReasons(base().query, ev({ ruleId: "5712" }))).toEqual(["SAME_RULE", "SHARED_RULE_GROUP"]);
    expect(classify([ev({ matchedIoc: false, ruleId: "5712" })]).events[0].correlation?.corroborated).toBe(false);
  });
});

describe("file deleted != recurrence", () => {
  const deletion = ev({ ruleId: "553", ruleGroups: ["syscheck"], filePath: "/home/finance/Downloads/Invoice.exe", fileOperation: "deleted" });

  it("deleting the searched artifact is CLEANUP: reported as ignored, never counted as activity", () => {
    // live case C: the EICAR hash matched rule 553 "File deleted"
    const r = classify([deletion]);
    expect(r.events[0].kind).toBe("CLEANUP");
    expect(r.ignoredEvents).toBe(1);
    expect(r.activityCount).toBe(0);
    expect(r.classification).toBe("NO_MATCH_COVERED");
  });

  it("a deletion plus a real re-appearance is still activity", () => {
    const r = classify(
      [deletion, ev({ id: "d2", ruleId: "554", ruleGroups: ["syscheck"], filePath: "/x", fileOperation: "added" })],
      { query: { hosts: ["attack-endpoint"], rule: { id: "554" } } }
    );
    expect(r.classification).toBe("IN_SCOPE_ACTIVITY");
    expect(r.ignoredEvents).toBe(1);
    expect(r.activityCount).toBe(1);
  });

  it("cleanup-only does not give a clean verdict when coverage is incomplete", () => {
    expect(classify([deletion], { coverage: incompleteCoverage }).classification).toBe("INCOMPLETE");
  });
});

describe("no matching alert != contained", () => {
  it("zero matches with complete coverage is NO_MATCH_COVERED", () => {
    expect(classify([]).classification).toBe("NO_MATCH_COVERED");
  });

  it.each([
    ["an agent coverage gap", { coverage: incompleteCoverage }],
    ["a window before the index starts", { coverage: { ...incompleteCoverage, windowCoveredByIndex: false, gaps: ["the window starts before the oldest indexed alert"] } }],
    ["skipped IOC types", { skippedIocTypes: ["DOMAIN"] }],
    ["a reached result cap", { complete: false, totalMatched: 5000 }],
  ])("zero fetched matches but %s is INCOMPLETE, never 'contained'", (_name, over) => {
    const r = classify([], over as Partial<ClassifyInput>);
    expect(r.classification).toBe("INCOMPLETE");
    expect(r.incompleteReasons.length).toBeGreaterThan(0);
  });

  it("a positive finding stands even when coverage is incomplete (only absence needs coverage)", () => {
    expect(classify([ev({ ruleId: "5712" })], { coverage: incompleteCoverage, complete: false, totalMatched: 3000 }).classification).toBe("IN_SCOPE_ACTIVITY");
  });

  it("uncorroborated matches are never read as 'contained' either", () => {
    expect(classify([ev({ host: "other", agentId: "010", ruleId: "9", ruleGroups: ["x"] })]).classification).toBe("UNCORROBORATED_MATCH");
  });

  it("when capped, the activity count is the total matched, not the fetched sample", () => {
    expect(classify([ev({ ruleId: "5712" })], { complete: false, totalMatched: 2500 }).activityCount).toBe(2500);
  });
});

describe("purity", () => {
  it("does not mutate its input and is deterministic", () => {
    const input = base({ events: [ev({ ruleId: "5712" })], totalMatched: 1 });
    const before = JSON.stringify(input);
    const a = classifyRehunt(input);
    const b = classifyRehunt(input);
    expect(JSON.stringify(input)).toBe(before);
    expect(a).toEqual(b);
  });
});
