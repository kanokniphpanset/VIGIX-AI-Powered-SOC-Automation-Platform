import * as fs from "node:fs";
import * as path from "node:path";
import {
  CorrelationCandidate,
  correlationIndicators,
  correlationLookup,
  correlationReasons,
  findCorrelatedIncident,
  isPrivateIp,
} from "../src/domain/alert/alertCorrelation";
import { IngestAlertFromSiemUseCase, IIncidentCorrelationReader } from "../src/application/alert/use-cases/IngestAlertFromSiem.usecase";
import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";
import { Alert } from "../src/domain/alert/entities/Alert.entity";
import { IAlertRepository } from "../src/domain/alert/repositories/IAlertRepository";
import { AbsorbIntoIncidentData, IIncidentRepository, MergeBlockedError } from "../src/domain/incident/repositories/IIncidentRepository";
import { Result } from "../src/shared/result/Result";

/** Automatic alert correlation at ingestion (the ATK-04 false-RESOLVED gap, .claude/cluade.md §45.7 issue 2). */

const FIXTURE_ROOT = path.resolve(__dirname, "../../../resources/mock-attacks");
type Obj = Record<string, any>;
interface Case {
  id: string;
  alert: Obj;
  relatedAlerts?: Obj[];
}
const cases: Case[] = fs
  .readdirSync(FIXTURE_ROOT, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .flatMap((d) => fs.readdirSync(path.join(FIXTURE_ROOT, d.name)).filter((f) => /^case-.*\.json$/.test(f)).map((f) => path.join(FIXTURE_ROOT, d.name, f)))
  .map((f) => JSON.parse(fs.readFileSync(f, "utf-8")) as Case)
  .sort((a, b) => a.id.localeCompare(b.id));
const byId = (id: string) => cases.find((c) => c.id === id)!;
const at = (a: Obj) => ({ rawPayload: a, receivedAt: new Date(a.timestamp) });
const incidentOf = (c: Case, extra: Partial<CorrelationCandidate> = {}): CorrelationCandidate => ({
  incidentId: c.id,
  openedAt: new Date(c.alert.timestamp),
  alerts: [at(c.alert)],
  iocs: [],
  ...extra,
});

const T0 = new Date("2026-09-18T12:00:00Z");
const hours = (h: number) => new Date(T0.getTime() + h * 3600_000);
const wazuh = (over: { host?: string; agentIp?: string; ruleId?: string; mitre?: string[]; data?: Obj }) => ({
  rule: { id: over.ruleId ?? "1000", level: 12, description: "test", mitre: { id: over.mitre ?? [] } },
  agent: { id: "001", name: over.host ?? "HOST-A", ip: over.agentIp ?? "10.0.0.10" },
  data: over.data ?? {},
});
const cand = (id: string, alerts: { rawPayload: unknown; receivedAt: Date }[], iocs: { iocType: string; value: string }[] = [], openedAt = alerts[0]?.receivedAt ?? T0): CorrelationCandidate => ({
  incidentId: id,
  openedAt,
  alerts,
  iocs,
});

describe("alertCorrelation — fixtures", () => {
  it("ATK-04: the C2 callback alert joins the malware incident (the process image IS the flagged file)", () => {
    const atk04 = byId("ATK-04");
    const m = correlationReasons(at(atk04.relatedAlerts![0]), incidentOf(atk04));
    expect(m).toEqual({ incidentId: "ATK-04", reasons: ["SHARED_IOC"], sharedIocs: ["c:\\users\\fin.analyst\\appdata\\roaming\\microsoft\\svchost32.exe"] });
  });

  it.each(cases.filter((c) => c.relatedAlerts?.length).map((c) => [c.id, c] as const))("%s: every related alert correlates with its primary", (_id, c) => {
    for (const r of c.relatedAlerts!) expect(correlationReasons(at(r), incidentOf(c))).not.toBeNull();
  });

  it("primary alerts of different cases correlate only where they share an attacker, a C2 or host + rule", () => {
    const pairs: string[] = [];
    for (const a of cases) {
      for (const b of cases) {
        if (a.id >= b.id) continue;
        // Window-free view: only WHICH facts relate them (fixture timestamps are days apart).
        const m = correlationReasons({ rawPayload: b.alert, receivedAt: T0 }, cand(a.id, [a.alert, ...(a.relatedAlerts ?? [])].map((x) => ({ rawPayload: x, receivedAt: T0 }))));
        if (m) pairs.push(`${a.id}~${b.id}:${m.reasons.join("+")}`);
      }
    }
    expect(pairs).toEqual([
      "ATK-01~ATK-02:SAME_HOST_TECHNIQUE+SAME_HOST_RULE", // SSH brute force on WKS-DEV-12, same rule
      "ATK-04~ATK-10:SHARED_IOC", // same C2 (45.155.205.233 / vigix-mock-c2.net)
      "ATK-05~ATK-06:SAME_HOST_TECHNIQUE+SAME_HOST_RULE", // SQL injection on WEB-01, same rule
      "ATK-07~ATK-08:SHARED_IOC+SAME_SOURCE_IP", // same external attacker 185.220.101.90
    ]);
  });

  it("ATK-03 and ATK-04 (same VirusTotal rule, different hosts and files) stay separate", () => {
    const m = correlationReasons({ rawPayload: byId("ATK-04").alert, receivedAt: T0 }, cand("ATK-03", [{ rawPayload: byId("ATK-03").alert, receivedAt: T0 }]));
    expect(m).toBeNull();
  });
});

describe("alertCorrelation — rules", () => {
  it("same host alone never correlates (different rule, technique, no shared indicator)", () => {
    const a = { rawPayload: wazuh({ ruleId: "1", mitre: ["T1110"] }), receivedAt: T0 };
    const b = { rawPayload: wazuh({ ruleId: "2", mitre: ["T1059"] }), receivedAt: hours(1) };
    expect(correlationReasons(b, cand("i", [a]))).toBeNull();
  });

  it("same host + same rule correlates within 24 h only", () => {
    const a = { rawPayload: wazuh({ ruleId: "5712" }), receivedAt: T0 };
    expect(correlationReasons({ rawPayload: wazuh({ ruleId: "5712" }), receivedAt: hours(23) }, cand("i", [a]))?.reasons).toEqual(["SAME_HOST_RULE"]);
    expect(correlationReasons({ rawPayload: wazuh({ ruleId: "5712" }), receivedAt: hours(25) }, cand("i", [a]))).toBeNull();
  });

  it("a public file hash correlates across hosts within 7 days, not after", () => {
    const sha = "61f0f070c5e6e8306a167aaf764b843a6fd337ca49a2f4f04b3e864b7cdb34eb";
    const a = { rawPayload: wazuh({ host: "HOST-A", ruleId: "1", data: { sha256: sha } }), receivedAt: T0 };
    const sixDays = correlationReasons({ rawPayload: wazuh({ host: "HOST-B", ruleId: "2", data: { sha256: sha } }), receivedAt: hours(6 * 24) }, cand("i", [a]));
    expect(sixDays).toMatchObject({ reasons: ["SHARED_IOC"], sharedIocs: [sha] });
    expect(correlationReasons({ rawPayload: wazuh({ host: "HOST-B", ruleId: "2", data: { sha256: sha } }), receivedAt: hours(8 * 24) }, cand("i", [a]))).toBeNull();
  });

  it("host-scoped indicators (file paths, private IPs) correlate only on the same host", () => {
    const pathA = { rawPayload: wazuh({ host: "HOST-A", ruleId: "1", data: { file: "C:\\Users\\bob\\evil-dropper.exe", dstip: "10.20.30.40" } }), receivedAt: T0 };
    const otherHost = wazuh({ host: "HOST-B", ruleId: "2", data: { file: "C:\\Users\\bob\\evil-dropper.exe", dstip: "10.20.30.40" } });
    expect(correlationReasons({ rawPayload: otherHost, receivedAt: hours(1) }, cand("i", [pathA]))).toBeNull();
    const sameHost = wazuh({ host: "HOST-A", ruleId: "2", data: { file: "C:\\Users\\bob\\evil-dropper.exe" } });
    expect(correlationReasons({ rawPayload: sameHost, receivedAt: hours(1) }, cand("i", [pathA]))?.sharedIocs).toEqual(["c:\\users\\bob\\evil-dropper.exe"]);
  });

  it("common system paths, short values and the agents' own IPs never count", () => {
    const ind = correlationIndicators(
      wazuh({ agentIp: "10.0.0.10", data: { file: "C:\\Windows\\System32\\cmd.exe", srcip: "10.0.0.10", process: "/usr/bin/bash", srcuser: "root", dstuser: "administrator", win: { eventdata: { image: "powershell.exe" } } } })
    );
    expect(ind).toEqual([]);
    const a = { rawPayload: wazuh({ host: "HOST-A", agentIp: "10.0.0.10", ruleId: "1", data: { file: "C:\\Windows\\System32\\cmd.exe" } }), receivedAt: T0 };
    const b = { rawPayload: wazuh({ host: "HOST-A", agentIp: "10.0.0.10", ruleId: "2", data: { file: "C:\\Windows\\System32\\cmd.exe", dstip: "10.0.0.10" } }), receivedAt: hours(1) };
    expect(correlationReasons(b, cand("i", [a]))).toBeNull();
  });

  it("a private source IP is no attacker identity across hosts", () => {
    const a = { rawPayload: wazuh({ host: "HOST-A", ruleId: "1", data: { srcip: "192.168.1.50" } }), receivedAt: T0 };
    expect(correlationReasons({ rawPayload: wazuh({ host: "HOST-B", ruleId: "2", data: { srcip: "192.168.1.50" } }), receivedAt: hours(1) }, cand("i", [a]))).toBeNull();
    expect(isPrivateIp("172.20.1.1") && isPrivateIp("fd00::1") && !isPrivateIp("185.220.101.90") && !isPrivateIp("172.32.0.1")).toBe(true);
  });

  it("indicators the incident records itself (e.g. a C2 IP carried by a re-hunt) correlate an alert from another host", () => {
    const primary = { rawPayload: wazuh({ host: "HOST-A", ruleId: "1" }), receivedAt: T0 };
    const c2 = { rawPayload: wazuh({ host: "HOST-B", ruleId: "2", data: { dstip: "45.155.205.233" } }), receivedAt: hours(30) };
    expect(correlationReasons(c2, cand("i", [primary]))).toBeNull();
    expect(correlationReasons(c2, cand("i", [primary], [{ iocType: "IPV4", value: "45.155.205.233" }]))).toMatchObject({ reasons: ["SHARED_IOC"], sharedIocs: ["45.155.205.233"] });
    // A recorded path has no host to compare: never correlates by itself.
    const pathAlert = { rawPayload: wazuh({ host: "HOST-B", ruleId: "2", data: { file: "C:\\Users\\bob\\evil-dropper.exe" } }), receivedAt: hours(1) };
    expect(correlationReasons(pathAlert, cand("i", [primary], [{ iocType: "FILE_PATH", value: "c:\\users\\bob\\evil-dropper.exe" }]))).toBeNull();
  });

  it("picks one incident: most shared indicators, then most reasons, then the newest", () => {
    const alert = { rawPayload: wazuh({ host: "HOST-A", ruleId: "5712", data: { dstip: "45.155.205.233", url: "http://bad.example.net/x.bin" } }), receivedAt: hours(2) };
    const byRule = cand("by-rule", [{ rawPayload: wazuh({ host: "HOST-A", ruleId: "5712" }), receivedAt: T0 }]);
    const oneIoc = cand("one-ioc", [{ rawPayload: wazuh({ host: "HOST-Z", ruleId: "9", data: { dstip: "45.155.205.233" } }), receivedAt: T0 }]);
    const twoIocs = cand("two-iocs", [{ rawPayload: wazuh({ host: "HOST-Z", ruleId: "9", data: { dstip: "45.155.205.233", url: "http://bad.example.net/x.bin" } }), receivedAt: T0 }]);
    expect(findCorrelatedIncident(alert, [byRule, oneIoc, twoIocs])?.incidentId).toBe("two-iocs");
    expect(findCorrelatedIncident(alert, [byRule, oneIoc])?.incidentId).toBe("one-ioc");
    const older = cand("older", byRule.alerts, [], hours(-5));
    const newer = cand("newer", byRule.alerts, [], hours(-1));
    expect(findCorrelatedIncident(alert, [older, newer])?.incidentId).toBe("newer");
    expect(findCorrelatedIncident(alert, [])).toBeNull();
  });

  it("the SQL lookup also searches the JSON-escaped form of a Windows path", () => {
    const l = correlationLookup(at(byId("ATK-04").relatedAlerts![0]));
    expect(l.host).toBe("wks-fin-07");
    expect(l.payloadNeedles).toContain("c:\\\\users\\\\fin.analyst\\\\appdata\\\\roaming\\\\microsoft\\\\svchost32.exe");
    expect(l.indicatorValues).toEqual(expect.arrayContaining(["45.155.205.233", "vigix-mock-c2.net", "http://vigix-mock-c2.net/stage2.bin"]));
  });
});

describe("IngestAlertFromSiemUseCase — automatic correlation", () => {
  const adapter = new WazuhAdapter();
  const TENANT = "00000000-0000-0000-0000-000000000001";
  const atk04 = byId("ATK-04");

  function setup(opts: { candidates?: CorrelationCandidate[]; readerFails?: boolean; absorbBlocked?: boolean; syncFails?: boolean; autoCreate?: boolean } = {}) {
    const saved: Alert[] = [];
    const alertRepository = {
      save: async (a: Alert) => (saved.push(a), a),
      findById: async (id: string) => saved.find((a) => a.id === id) ?? null,
      findByExternalId: async (source: string, ext: string) => saved.filter((a) => a.siemSource === source && a.externalAlertId === ext),
    } as unknown as IAlertRepository;
    const absorbed: AbsorbIntoIncidentData[] = [];
    const incidentRepository = {
      findLinkedIncidents: async () => new Map(),
      absorbIntoIncident: async (d: AbsorbIntoIncidentData) => {
        if (opts.absorbBlocked) throw new MergeBlockedError("TARGET_NOT_OPEN", d.targetIncidentId);
        absorbed.push(d);
        return d.unlinkedAlertIds;
      },
    } as unknown as IIncidentRepository;
    const created: string[][] = [];
    const createIncident = { execute: async (input: { alertIds: string[] }) => (created.push(input.alertIds), Result.ok({ id: "new-incident" } as never)) };
    const queue = { enqueue: async () => ({}) as never, latestForIncident: async (incidentId: string) => ({ id: `job-of-${incidentId}`, status: "SUCCEEDED" }) as never };
    const audits: { action: string; metadata?: Record<string, unknown> }[] = [];
    const auditLogger = { record: async (e: { action: string; metadata?: Record<string, unknown> }) => void audits.push(e) } as never;
    const lookups: unknown[] = [];
    const reader: IIncidentCorrelationReader = {
      openCandidates: async (q) => {
        lookups.push(q);
        if (opts.readerFails) throw new Error("db down");
        return opts.candidates ?? [];
      },
    };
    const synced: string[] = [];
    const investigations = {
      syncIncident: async (id: string) => {
        if (opts.syncFails) throw new Error("sync down");
        synced.push(id);
      },
    };
    const intake = { evaluate: async (i: { severity: string }) => ({ autoCreateIncident: opts.autoCreate ?? ["high", "critical"].includes(i.severity.toLowerCase()), matchedPolicies: ["RULE-I03"] }) };
    const useCase = new IngestAlertFromSiemUseCase(alertRepository, incidentRepository, queue, auditLogger, intake, createIncident as never, { reader, investigations });
    return { useCase, saved, absorbed, created, audits, lookups, synced };
  }
  const ingest = (useCase: IngestAlertFromSiemUseCase, raw: Obj) => useCase.execute({ ...adapter.normalize(raw as never), tenantId: TENANT });
  const primaryIncident = incidentOf(atk04, { incidentId: "primary-incident" });

  it("ATK-04 related alert joins the open primary incident: linked, synced, audited — no second incident", async () => {
    const { useCase, saved, absorbed, created, audits, synced } = setup({ candidates: [primaryIncident] });
    const r = await ingest(useCase, atk04.relatedAlerts![0]);
    expect(r.value).toMatchObject({
      incidentId: "primary-incident",
      aiJob: { id: "job-of-primary-incident", status: "SUCCEEDED" },
      duplicate: false,
      triageRequired: false,
      correlation: { incidentId: "primary-incident", reasons: ["SHARED_IOC"] },
    });
    expect(created).toEqual([]);
    expect(absorbed).toHaveLength(1);
    expect(absorbed[0]).toMatchObject({ tenantId: TENANT, targetIncidentId: "primary-incident", sourceIncidentIds: [], unlinkedAlertIds: [saved[0].id], actor: "vigix-ingest" });
    expect(absorbed[0].timelineDescription!("1726657860.10005")).toMatch(/^Alert 1726657860\.10005 correlated into the incident automatically \(SHARED_IOC: c:\\users/);
    expect(synced).toEqual(["primary-incident"]);
    expect(audits.map((a) => a.action)).toEqual(["ALERT_CORRELATED_TO_INCIDENT"]);
    expect(audits[0].metadata).toMatchObject({ alertId: saved[0].id, incidentId: "primary-incident", reasons: ["SHARED_IOC"], trigger: "AUTOMATIC", matchedPolicies: ["RULE-I03"] });
  });

  it("nothing related open -> a new incident as before", async () => {
    const { useCase, created, absorbed, audits } = setup({ candidates: [incidentOf(byId("ATK-03"))] });
    const r = await ingest(useCase, atk04.relatedAlerts![0]);
    expect(r.value.incidentId).toBe("new-incident");
    expect(r.value.correlation).toBeUndefined();
    expect(created).toHaveLength(1);
    expect(absorbed).toEqual([]);
    expect(audits.map((a) => a.action)).toEqual(["ALERT_ESCALATED_TO_INCIDENT"]);
  });

  it("a failed lookup or an incident closed meanwhile never loses the alert: a new incident is opened", async () => {
    for (const opts of [{ readerFails: true }, { absorbBlocked: true }]) {
      const { useCase, created, audits } = setup({ candidates: [primaryIncident], ...opts });
      const r = await ingest(useCase, atk04.relatedAlerts![0]);
      expect(r.value.incidentId).toBe("new-incident");
      expect(created).toHaveLength(1);
      expect(audits.map((a) => a.action)).toEqual(["ALERT_ESCALATED_TO_INCIDENT"]);
    }
  });

  it("a failed investigation sync does not undo the correlation (the read path syncs again)", async () => {
    const { useCase, created } = setup({ candidates: [primaryIncident], syncFails: true });
    const r = await ingest(useCase, atk04.relatedAlerts![0]);
    expect(r.value.correlation?.incidentId).toBe("primary-incident");
    expect(created).toEqual([]);
  });

  it("alerts that would not open an incident (MEDIUM -> Alert Inbox) are never correlated automatically", async () => {
    const { useCase, lookups, absorbed } = setup({ candidates: [primaryIncident], autoCreate: false });
    const r = await ingest(useCase, atk04.relatedAlerts![0]);
    expect(r.value).toMatchObject({ incidentId: null, triageRequired: true });
    expect(lookups).toEqual([]);
    expect(absorbed).toEqual([]);
  });
});
