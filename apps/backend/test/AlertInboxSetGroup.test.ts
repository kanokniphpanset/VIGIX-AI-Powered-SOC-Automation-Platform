import { relatedReasons, summarizeAlert } from "../src/domain/alert/alertSummary";
import { MergeAlertsIntoIncidentUseCase } from "../src/application/incident/use-cases/MergeAlertsIntoIncident.usecase";
import { IIncidentRepository, MergeBlockedError } from "../src/domain/incident/repositories/IIncidentRepository";
import { IAlertRepository } from "../src/domain/alert/repositories/IAlertRepository";
import { IInvestigationRepository } from "../src/domain/investigation/IInvestigationRepository";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";

/** Frontend P0 backend support: Alert Inbox relatedness (facts only) and Set Group merge. */

const wazuh = (over: { srcip?: string; agent?: string; mitre?: string[]; rule?: string }) => ({
  rule: { id: over.rule ?? "5712", description: "sshd: brute force", level: 10, mitre: { id: over.mitre ?? ["T1110"] } },
  agent: { id: "012", name: over.agent ?? "WKS-DEV-12", ip: "10.0.5.44" },
  data: { srcip: over.srcip ?? "185.220.101.45", dstuser: "root" },
});
const at = (min: number) => new Date(Date.UTC(2026, 8, 23, 10, min));
const entry = (payload: unknown, min: number) => ({ summary: summarizeAlert(payload), receivedAt: at(min) });

describe("summarizeAlert", () => {
  it("reads rule, MITRE, source IP, host, agent IP and user from the Wazuh payload as received", () => {
    expect(summarizeAlert(wazuh({}))).toEqual({
      ruleId: "5712",
      ruleDescription: "sshd: brute force",
      ruleLevel: 10,
      mitreTechniques: ["T1110"],
      sourceIp: "185.220.101.45",
      destinationIp: null,
      host: "WKS-DEV-12",
      agentIp: "10.0.5.44",
      user: "root",
    });
  });
  it("leaves absent fields empty instead of guessing", () => {
    expect(summarizeAlert({})).toMatchObject({ ruleId: null, sourceIp: null, host: null, mitreTechniques: [] });
  });
});

describe("relatedReasons", () => {
  it("same source IP -> related, with every shared fact and the time window", () => {
    expect(relatedReasons(entry(wazuh({}), 0), entry(wazuh({}), 5))).toEqual(["SAME_SOURCE_IP", "SAME_TARGET_HOST", "SAME_TECHNIQUE", "SAME_RULE", "SAME_TIME_WINDOW"]);
  });
  it("same host + same technique (different source) -> related; outside 1 h no time-window reason", () => {
    expect(relatedReasons(entry(wazuh({}), 0), entry(wazuh({ srcip: "1.2.3.4", rule: "9999" }), 180))).toEqual(["SAME_TARGET_HOST", "SAME_TECHNIQUE"]);
  });
  it("same host only, or same time window only, is NOT related", () => {
    expect(relatedReasons(entry(wazuh({}), 0), entry(wazuh({ srcip: "1.2.3.4", mitre: ["T1059.001"], rule: "1" }), 1))).toEqual([]);
    expect(relatedReasons(entry(wazuh({}), 0), entry(wazuh({ srcip: "1.2.3.4", agent: "WEB-01", mitre: ["T1190"], rule: "1" }), 1))).toEqual([]);
  });
});

describe("MergeAlertsIntoIncidentUseCase (Set Group)", () => {
  function world(opts: { linked?: Record<string, string>; block?: MergeBlockedError } = {}) {
    const audit: Array<{ action: string; metadata?: Record<string, unknown> }> = [];
    const absorbed: unknown[] = [];
    const synced: string[] = [];
    const incidents = {
      findById: async (id: string) => (id === "INC-A" ? { id } : null),
      findLinkedIncidents: async (ids: string[]) => new Map(ids.filter((i) => opts.linked?.[i]).map((i) => [i, opts.linked![i]])),
      absorbIntoIncident: async (d: { sourceIncidentIds: string[]; unlinkedAlertIds: string[] }) => {
        if (opts.block) throw opts.block;
        absorbed.push(d);
        return ["a2", "a3"];
      },
    } as unknown as IIncidentRepository;
    const alerts = { findById: async (id: string) => (id.startsWith("a") ? { id } : null) } as unknown as IAlertRepository;
    const investigations = { syncIncident: async (id: string) => void synced.push(id) } as unknown as IInvestigationRepository;
    const auditLogger = { record: async (e: (typeof audit)[number]) => void audit.push(e) } as unknown as AuditLogger;
    const useCase = new MergeAlertsIntoIncidentUseCase(incidents, alerts, investigations, auditLogger);
    const run = (alertIds: string[]) => useCase.execute({ tenantId: "t", incidentId: "INC-A", alertIds, actor: "soc-1" });
    return { run, audit, absorbed, synced };
  }

  it("moves linked alerts' incidents + unlinked alerts into the target, syncs its investigation, audits", async () => {
    const w = world({ linked: { a1: "INC-A", a2: "INC-B" } });
    const r = await w.run(["a1", "a2", "a3"]);
    expect(r.isSuccess).toBe(true);
    expect(w.absorbed).toEqual([{ tenantId: "t", targetIncidentId: "INC-A", sourceIncidentIds: ["INC-B"], unlinkedAlertIds: ["a3"], actor: "soc-1" }]);
    expect(w.synced).toEqual(["INC-A"]);
    expect(w.audit[0]).toMatchObject({ action: "ALERTS_MERGED", metadata: { mergedIncidentIds: ["INC-B"], addedAlertIds: ["a2", "a3"] } });
  });

  it("a source incident with response work (or resolved) blocks the merge; nothing synced or audited", async () => {
    for (const reason of ["SOURCE_HAS_RESPONSE", "SOURCE_RESOLVED", "TARGET_NOT_OPEN"] as const) {
      const w = world({ linked: { a2: "INC-B" }, block: new MergeBlockedError(reason, "INC-B") });
      const r = await w.run(["a2"]);
      expect(r.error).toEqual({ code: reason, incidentId: "INC-B" });
      expect(w.synced).toEqual([]);
      expect(w.audit).toEqual([]);
    }
  });

  it("unknown alert or incident -> not found, nothing written", async () => {
    const w = world();
    expect((await w.run(["zzz"])).error).toEqual({ code: "ALERT_NOT_FOUND", alertIds: ["zzz"] });
    expect(w.absorbed).toEqual([]);
  });
});

// The legacy merge contract remains covered above; the SOC Inbox must never surface grouping.
it("inbox and alert detail use the single-alert review dialog: no grouping, no claim / owner, no test scenario", () => {
  const fs = require("node:fs"); const path = require("node:path");
  for (const name of ["AlertInboxView.vue", "AlertDetailView.vue"]) {
    const source = fs.readFileSync(path.join(__dirname, "../../src/views/alerts", name), "utf8");
    expect(source).toContain("AlertReviewDialog");
    expect(source).not.toMatch(/SetGroupModal|Related to|Send email|analyzing/);
    expect(source).not.toMatch(/alertsApi\.claim|alertsApi\.release|Continue Triage|Release claim|owner|setScenario|Test scenario/);
  }
  expect(fs.existsSync(path.join(__dirname, "../../src/components/alerts/SetGroupModal.vue"))).toBe(false);
  expect(fs.existsSync(path.join(__dirname, "../../src/components/alerts/TriagePanel.vue"))).toBe(false);
});
