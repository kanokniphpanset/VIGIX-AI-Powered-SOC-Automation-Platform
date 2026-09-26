import * as fs from "node:fs";
import * as path from "node:path";

import { extractAlertIocs, REHUNT_IOC_TYPES } from "../src/domain/investigation/alertIocs";
import { checkIocValue } from "../src/application/investigation/iocValidation";
import { buildRehuntDsl } from "../src/infrastructure/external-services/siem/WazuhIndexerAdapter";
import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";
import { IngestAlertFromSiemUseCase } from "../src/application/alert/use-cases/IngestAlertFromSiem.usecase";
import { IAlertRepository } from "../src/domain/alert/repositories/IAlertRepository";
import { IIncidentRepository } from "../src/domain/incident/repositories/IIncidentRepository";
import { Alert } from "../src/domain/alert/entities/Alert.entity";
import { AiAnalysisJob, AiJobTrigger } from "../src/application/agent-orchestration/ports/IAiAnalysisJobRepository";
import { CreateIncidentWithAlertsData } from "../src/domain/incident/repositories/IIncidentRepository";

/**
 * Task 6 — Alert -> Incident -> Investigation -> Evidence/IOC.
 * Uses the mock attack fixtures (resources/mock-attacks/) as input.
 */

const FIXTURE_ROOT = path.resolve(__dirname, "../../../resources/mock-attacks");

type Obj = Record<string, unknown>;
interface Round {
  round: number;
  scenario: string;
  events: Obj[];
}
interface Case {
  id: string;
  alert: Obj & { id: string };
  relatedAlerts?: Obj[];
  expected: { iocs: Array<{ type: string; value: string }> };
  rehunt: { rounds: Round[] };
}

const cases: Case[] = fs
  .readdirSync(FIXTURE_ROOT, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .flatMap((d) => fs.readdirSync(path.join(FIXTURE_ROOT, d.name)).filter((f) => /^case-.*\.json$/.test(f)).map((f) => path.join(FIXTURE_ROOT, d.name, f)))
  .sort()
  .map((f) => JSON.parse(fs.readFileSync(f, "utf-8")) as Case);

/** Fixture IOC vocabulary -> backend IocType(s) it may be stored as. */
const TYPE_MAP: Record<string, string[]> = {
  ip: ["IPV4", "IPV6"],
  domain: ["DOMAIN"],
  url: ["URL"],
  hash: ["MD5", "SHA1", "SHA256"],
  registry: ["REGISTRY_KEY"],
  file: ["FILE_PATH"],
  process: ["PROCESS_NAME"],
  command: ["COMMAND_LINE"],
  user: ["USERNAME"],
  request: ["HTTP_REQUEST"],
};

// The indexer fields an IOC is phrase-matched against — read from the real query builder.
const INDEXER_IOC_FIELDS: string[] = (() => {
  const dsl = buildRehuntDsl({
    incidentId: "i",
    responseId: "r",
    hosts: [],
    iocs: [{ type: "ip", value: "1.1.1.1" }],
    timeRange: { start: new Date(0), end: new Date(1) },
  }) as { query: { bool: { should: Array<{ bool: { should: Array<{ multi_match: { fields: string[] } }> } }> } } };
  return dsl.query.bool.should[0].bool.should[0].multi_match.fields;
})();

function dig(o: unknown, dotted: string): unknown {
  return dotted.split(".").reduce<unknown>((n, k) => (n && typeof n === "object" ? (n as Obj)[k] : undefined), o);
}

describe("extractAlertIocs over the 10 mock attack fixtures", () => {
  it("has the 10 cases", () => {
    expect(cases.map((c) => c.id).sort()).toEqual(["ATK-01", "ATK-02", "ATK-03", "ATK-04", "ATK-05", "ATK-06", "ATK-07", "ATK-08", "ATK-09", "ATK-10"]);
  });

  describe.each(cases.map((c) => [c.id, c] as const))("%s", (_id, c) => {
    const alerts = [c.alert, ...(c.relatedAlerts ?? [])];
    const extracted = alerts.flatMap((a) => extractAlertIocs(a));

    it("extracts every expected IOC with a backend IOC type", () => {
      for (const ioc of c.expected.iocs) {
        const types = TYPE_MAP[ioc.type];
        const hit = extracted.find((e) => types.includes(e.iocType) && e.value.toLowerCase().includes(ioc.value.toLowerCase()));
        expect({ ioc, found: !!hit }).toEqual({ ioc, found: true });
      }
    });

    it("every extracted IOC passes the existing IOC validation", () => {
      for (const e of extracted) {
        const checked = checkIocValue(e.iocType, e.value);
        expect({ e, ok: checked.ok }).toEqual({ e, ok: true });
      }
    });

    it("never turns a NO_MATCH re-hunt round into a match (only re-hunt IOC types are hunted)", () => {
      const hunted = extracted.filter((e) => REHUNT_IOC_TYPES.includes(e.iocType)).map((e) => e.value.toLowerCase());
      for (const round of c.rehunt.rounds.filter((r) => r.scenario === "NO_MATCH")) {
        for (const event of round.events) {
          const haystacks = INDEXER_IOC_FIELDS.map((f) => dig(event, f)).filter((v) => v !== undefined && v !== null).map((v) => String(v).toLowerCase());
          const matched = hunted.filter((v) => haystacks.some((h) => h.includes(v)));
          expect({ round: round.round, event: event.id, matched }).toEqual({ round: round.round, event: event.id, matched: [] });
        }
      }
    });
  });

  it("does not report a group as a user on group-membership events (ATK-08)", () => {
    const atk08 = cases.find((c) => c.id === "ATK-08")!;
    const users = extractAlertIocs(atk08.alert).filter((e) => e.iocType === "USERNAME").map((e) => e.value);
    expect(users).toContain("j.smith");
    expect(users).not.toContain("Domain Admins");
  });

  it("returns nothing for a payload without indicator fields and never throws on junk", () => {
    expect(extractAlertIocs({ rule: { description: "x" }, agent: { name: "h" } })).toEqual([]);
    expect(extractAlertIocs(null)).toEqual([]);
    expect(extractAlertIocs("not an object")).toEqual([]);
  });
});

describe("IngestAlertFromSiemUseCase -> Alert Inbox (SOC triage), never an automatic incident", () => {
  const adapter = new WazuhAdapter();
  const atk01 = cases.find((c) => c.id === "ATK-01")!;
  const TENANT = "00000000-0000-0000-0000-000000000001";

  function setup(opts: { incidentFails?: boolean; enqueueFails?: boolean } = {}) {
    const saved: Alert[] = [];
    const alertRepository = {
      save: async (a: Alert) => (saved.push(a), a),
      findByExternalId: async (source: string, ext: string) => saved.filter((a) => a.siemSource === source && a.externalAlertId === ext),
    } as unknown as IAlertRepository;
    const incidents: CreateIncidentWithAlertsData[] = [];
    const links = new Map<string, string>();
    const incidentRepository = {
      createWithAlerts: async (data: CreateIncidentWithAlertsData) => {
        if (opts.incidentFails) throw new Error("db down");
        incidents.push(data);
        const id = `incident-${incidents.length}`;
        data.alertIds.forEach((a) => links.set(a, id));
        return { id };
      },
      findLinkedIncidents: async (ids: string[]) => new Map(ids.filter((i) => links.has(i)).map((i) => [i, links.get(i)!])),
    } as unknown as IIncidentRepository;
    const jobs: AiAnalysisJob[] = [];
    const queue = {
      enqueue: async (input: { tenantId: string; incidentId: string; alertId: string; trigger: AiJobTrigger }) => {
        if (opts.enqueueFails) throw new Error("db down");
        const job = { ...input, id: `job-${jobs.length + 1}`, status: "QUEUED", attempt: 1 } as AiAnalysisJob;
        jobs.push(job);
        return job;
      },
      latestForIncident: async (incidentId: string) => [...jobs].reverse().find((j) => j.incidentId === incidentId) ?? null,
    };
    const audits: Array<{ action: string; metadata?: Record<string, unknown> }> = [];
    const auditLogger = { record: async (e: { action: string; metadata?: Record<string, unknown> }) => void audits.push(e) } as never;
    const useCase = new IngestAlertFromSiemUseCase(alertRepository, incidentRepository, queue, auditLogger);
    return { useCase, saved, incidents, jobs, audits };
  }

  const run = (useCase: IngestAlertFromSiemUseCase) => useCase.execute({ ...adapter.normalize(atk01.alert), tenantId: TENANT });

  it("stores the alert for SOC triage: no incident, no AI job, ALERT_ROUTED_TO_TRIAGE audited", async () => {
    const { useCase, saved, incidents, jobs, audits } = setup();
    const r = await run(useCase);
    expect(r.value).toMatchObject({ incidentId: null, aiJob: null, duplicate: false, triageRequired: true });
    expect(saved).toHaveLength(1);
    expect(saved[0].status).toBe("received");
    expect(incidents).toEqual([]);
    expect(jobs).toEqual([]);
    expect(audits.map((a) => a.action)).toEqual(["ALERT_ROUTED_TO_TRIAGE"]);
    expect(audits[0].metadata).toMatchObject({ severity: saved[0].severity, assignedRole: "SOC", siemSource: "wazuh" });
  });

  it("is idempotent: the same SIEM alert again creates no alert, incident or job", async () => {
    const { useCase, saved, incidents, jobs } = setup();
    await run(useCase);
    const again = await run(useCase);
    expect(again.value).toMatchObject({ duplicate: true, incidentId: null, aiJob: null, triageRequired: false });
    expect(again.value.alert.id).toBe(saved[0].id);
    expect(saved).toHaveLength(1);
    expect(incidents).toEqual([]);
    expect(jobs).toEqual([]);
  });

  it("a duplicate of an alert the SOC already put in an incident reports that incident and its latest AI job", async () => {
    const { useCase, saved } = setup();
    const first = await run(useCase);
    // SOC action (CreateIncidentUseCase) — simulated through the same repository the duplicate lookup reads.
    const linkedRepo = (useCase as unknown as { incidentRepository: { createWithAlerts: (d: unknown) => Promise<{ id: string }> } }).incidentRepository;
    await linkedRepo.createWithAlerts({ tenantId: TENANT, title: "SOC incident", priority: "high", alertIds: [first.value.alert.id], createdBy: "soc@x", note: null });
    const again = await run(useCase);
    expect(again.value).toMatchObject({ duplicate: true, incidentId: "incident-1", triageRequired: false });
    expect(saved).toHaveLength(1);
  });

  it("never touches the incident store or the AI queue, even when both are down", async () => {
    const { useCase, saved, incidents, jobs } = setup({ incidentFails: true, enqueueFails: true });
    const r = await run(useCase);
    expect(r.isSuccess).toBe(true);
    expect(r.value).toMatchObject({ incidentId: null, aiJob: null, duplicate: false, triageRequired: true });
    expect(saved).toHaveLength(1);
    expect(incidents).toEqual([]);
    expect(jobs).toEqual([]);
  });
});
