import * as fs from "node:fs";
import * as path from "node:path";

import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";
import { IngestAlertFromSiemUseCase } from "../src/application/alert/use-cases/IngestAlertFromSiem.usecase";
import { IAlertRepository } from "../src/domain/alert/repositories/IAlertRepository";
import { Alert } from "../src/domain/alert/entities/Alert.entity";
import { IIncidentRepository } from "../src/domain/incident/repositories/IIncidentRepository";
import { AiAnalysisJob } from "../src/application/agent-orchestration/ports/IAiAnalysisJobRepository";

/**
 * Mock Wazuh attack fixtures (resources/mock-attacks/) -> backend ingestion.
 * Fixture schema, AI normalization and re-hunt round consistency are covered by
 * apps/ai-orchestrator/tests/fixtures/test_mock_attack_fixtures.py.
 */

const FIXTURE_ROOT = path.resolve(__dirname, "../../../resources/mock-attacks");
const TENANT_ID = "00000000-0000-0000-0000-000000000001";

interface MockAttackCase {
  id: string;
  alert: Record<string, unknown> & { id: string; timestamp: string };
  relatedAlerts?: Array<Record<string, unknown> & { id: string; timestamp: string }>;
  expected: { severity: string; host: string };
}

function loadCases(): Array<{ file: string; data: MockAttackCase }> {
  return fs
    .readdirSync(FIXTURE_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .flatMap((d) =>
      fs
        .readdirSync(path.join(FIXTURE_ROOT, d.name))
        .filter((f) => /^case-.*\.json$/.test(f))
        .map((f) => `${d.name}/${f}`)
    )
    .sort()
    .map((file) => ({ file, data: JSON.parse(fs.readFileSync(path.join(FIXTURE_ROOT, file), "utf-8")) as MockAttackCase }));
}

class InMemoryAlertRepository implements IAlertRepository {
  readonly saved: Alert[] = [];
  async findById(id: string): Promise<Alert | null> {
    return this.saved.find((a) => a.id === id) ?? null;
  }
  async findAll(): Promise<Alert[]> {
    return [...this.saved];
  }
  async countAll(): Promise<number> {
    return this.saved.length;
  }
  async findByExternalId(siemSource: string, externalAlertId: string): Promise<Alert[]> {
    return this.saved.filter((a) => a.siemSource === siemSource && a.externalAlertId === externalAlertId);
  }
  async save(alert: Alert): Promise<Alert> {
    this.saved.push(alert);
    return alert;
  }
  // Triage lifecycle — ingestion never claims, triages or reviews (SOC actions); unreachable here.
  async claim(): Promise<never> {
    throw new Error("not used by ingestion");
  }
  async release(): Promise<boolean> {
    throw new Error("not used by ingestion");
  }
  async commitTriage(): Promise<Alert | null> {
    throw new Error("not used by ingestion");
  }
  async findDueMonitors(): Promise<Alert[]> {
    return [];
  }
  async returnDueMonitor(): Promise<Alert | null> {
    return null;
  }
  async recordTriage(): Promise<Alert> {
    throw new Error("not used by ingestion");
  }
}

/** Backend-side incident creation + AI job queue, recorded (ingestion never runs the AI itself). */
function recordingPipeline(queueFails = false) {
  const incidents: string[][] = [];
  const queued: Array<{ incidentId: string; alertId: string }> = [];
  const incidentRepository = {
    createWithAlerts: async (data: { alertIds: string[] }) => (incidents.push(data.alertIds), { id: `incident-${incidents.length}` }),
    findLinkedIncidents: async () => new Map<string, string>(),
  } as unknown as IIncidentRepository;
  const queue = {
    enqueue: async (input: { incidentId: string; alertId: string }) => {
      if (queueFails) throw new Error("queue unavailable");
      queued.push(input);
      return { id: `job-${queued.length}`, status: "QUEUED" } as AiAnalysisJob;
    },
    latestForIncident: async () => null,
  };
  return { incidentRepository, queue, incidents, queued };
}

const cases = loadCases();
const adapter = new WazuhAdapter();

describe("Mock attack fixtures -> backend ingestion", () => {
  it("finds fixture case files", () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  describe.each(cases.map((c) => [c.data.id, c] as const))("%s", (_id, { data }) => {
    const alerts = [data.alert, ...(data.relatedAlerts ?? [])];

    it("normalizes through WazuhAdapter with the expected severity", () => {
      const normalized = adapter.normalize(data.alert);
      expect(normalized.siemSource).toBe("wazuh");
      expect(normalized.externalAlertId).toBe(data.alert.id);
      expect(normalized.severity).toBe(data.expected.severity);
      expect(normalized.receivedAt.toISOString()).toBe(new Date(data.alert.timestamp).toISOString());
      expect(normalized.rawPayload).toEqual(data.alert);
    });

    it("ingests every alert into the Alert Inbox for SOC triage (no automatic incident or AI job)", async () => {
      const repo = new InMemoryAlertRepository();
      const { incidentRepository, queue, incidents, queued } = recordingPipeline();
      const useCase = new IngestAlertFromSiemUseCase(repo, incidentRepository, queue);

      for (const alert of alerts) {
        const result = await useCase.execute({ ...adapter.normalize(alert), tenantId: TENANT_ID });
        expect(result.isSuccess).toBe(true);
        expect(result.value.aiJob).toBeNull();
        expect(result.value.incidentId).toBeNull();
        expect(result.value.triageRequired).toBe(true);
        expect(result.value.duplicate).toBe(false);
        expect(result.value.alert.status).toBe("received");
      }

      expect(repo.saved.map((a) => a.externalAlertId)).toEqual(alerts.map((a) => a.id));
      expect(incidents).toEqual([]);
      expect(queued).toEqual([]);
      expect((repo.saved[0].rawPayload as { agent: { name: string } }).agent.name).toBe(data.expected.host);
    });

    it("stores the alert even when the AI queue is unavailable (ingestion never uses it)", async () => {
      const repo = new InMemoryAlertRepository();
      const { incidentRepository, queue, incidents } = recordingPipeline(true);
      const useCase = new IngestAlertFromSiemUseCase(repo, incidentRepository, queue);
      const errorSpy = jest.spyOn(console, "error").mockImplementation(() => undefined);

      const result = await useCase.execute({ ...adapter.normalize(data.alert), tenantId: TENANT_ID });

      errorSpy.mockRestore();
      expect(result.isSuccess).toBe(true);
      expect(result.value.aiJob).toBeNull();
      expect(repo.saved).toHaveLength(1);
      expect(incidents).toEqual([]);
    });
  });

  it("rejects a Wazuh payload without rule.description (invalid alert)", () => {
    const { alert } = cases[0].data;
    const broken = { ...alert, rule: { ...(alert.rule as object), description: undefined } };
    expect(() => adapter.normalize(broken)).toThrow(/missing rule.description/);
  });
});
