import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { isMockAlertKey, mockCaseOf, mockExternalAlertId, mockExternalIdMatch, mockKeyOfExternalId, MockAlertCase } from "../src/domain/alert/mockAlerts";
import { FileMockAlertCatalog, IMockAlertCatalog, MockAlertFixture } from "../src/infrastructure/mock-alerts/FileMockAlertCatalog";
import { SendMockAlertUseCase } from "../src/application/alert/use-cases/SendMockAlert.usecase";
import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";
import { buildMockAlertRoutes, mockAlertSendingEnabled } from "../src/presentation/http/routes/mock-alert.routes";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { Result } from "../src/shared/result/Result";

const tc = (n: string, fixtureAlertId: string | null = null): MockAlertCase => ({
  key: `TC-${n}`, set: "TC", title: "t", attackType: "t", file: `mock-attacks-tc/TC-${n}-x.json`, fixtureAlertId, ruleId: "5712", ruleLevel: 10, ruleDescription: "d", host: "h",
});

describe("mock alert ids (domain)", () => {
  test("keys: TC-nn and MOCK-ATK-nn only", () => {
    expect(["TC-01", "TC-10", "MOCK-ATK-03"].every(isMockAlertKey)).toBe(true);
    expect(["ATK-01", "tc-1", "TC-1", "../etc", "MOCK-ATK-1", ""].some(isMockAlertKey)).toBe(false);
  });

  test("a sent mock alert's external id carries its key and round-trips", () => {
    const id = mockExternalAlertId("MOCK-ATK-03", new Date(1_790_000_000_000), "a1b2c3");
    expect(id).toBe("mock-MOCK-ATK-03-1790000000000-a1b2c3");
    expect(mockKeyOfExternalId(id)).toBe("MOCK-ATK-03");
    expect(mockKeyOfExternalId("1790675711.710582")).toBeNull();
    expect(mockKeyOfExternalId("mock-ATK-03-1-a")).toBeNull(); // lab scenario ids are not mock keys
  });

  test("inbox match: one case (prefix + legacy fixture id), all mocks, unknown key matches nothing, no filter", () => {
    const cases = [tc("01", "1727659920.20001"), tc("02")];
    expect(mockExternalIdMatch("TC-01", cases)).toEqual({ prefixes: ["mock-TC-01-"], exact: ["1727659920.20001"] });
    expect(mockExternalIdMatch("all", cases)).toEqual({ prefixes: ["mock-"], exact: ["1727659920.20001"] });
    expect(mockExternalIdMatch("TC-99", cases)).toEqual({ prefixes: [], exact: [] });
    expect(mockExternalIdMatch(undefined, cases)).toBeNull();
  });

  test("mockCaseOf: by mock id, by legacy fixture id, else null", () => {
    const cases = [tc("01", "1727659920.20001"), tc("02")];
    expect(mockCaseOf("mock-TC-02-1-abc", cases)?.key).toBe("TC-02");
    expect(mockCaseOf("1727659920.20001", cases)?.key).toBe("TC-01");
    expect(mockCaseOf("1790675711.710582", cases)).toBeNull();
  });
});

describe("FileMockAlertCatalog (the real resources/ fixtures)", () => {
  const catalog = new FileMockAlertCatalog();
  test("loads 10 TC + 10 MOCK-ATK cases with valid keys and a Wazuh rule each", () => {
    const keys = catalog.list().map((c) => c.key);
    expect(keys.filter((k) => k.startsWith("TC-"))).toEqual(Array.from({ length: 10 }, (_, i) => `TC-${String(i + 1).padStart(2, "0")}`));
    expect(keys.filter((k) => k.startsWith("MOCK-ATK-"))).toEqual(Array.from({ length: 10 }, (_, i) => `MOCK-ATK-${String(i + 1).padStart(2, "0")}`));
    for (const c of catalog.list()) {
      expect(isMockAlertKey(c.key)).toBe(true);
      expect(c.ruleId).toBeTruthy();
      expect(() => new WazuhAdapter().normalize(c.alert)).not.toThrow();
    }
    expect(catalog.find("tc-05")?.file).toBe("mock-attacks-tc/TC-05-powershell.json");
  });
});

describe("SendMockAlertUseCase", () => {
  const fixture: MockAlertFixture = {
    ...tc("01", "1727659920.20001"),
    alert: { id: "1727659920.20001", timestamp: "2026-09-30T01:12:00.000+0000", rule: { id: "5712", level: 10, description: "sshd brute force" }, agent: { id: "003", name: "WEB-01" }, data: { srcip: "185.220.101.45" } },
  };
  const catalog: IMockAlertCatalog = { list: () => [fixture], find: (k) => (k.toUpperCase() === "TC-01" ? fixture : null) };

  test("ingests through the Wazuh adapter with a fresh mock id + timestamp; the fixture is untouched; audited", async () => {
    const ingested: Record<string, unknown>[] = [];
    const audit: Record<string, unknown>[] = [];
    const ingest = {
      execute: async (input: Record<string, unknown>) => {
        ingested.push(input);
        return Result.ok({ alert: { id: "alert-1", severity: "high" }, incidentId: "inc-1", aiJob: null, duplicate: false, triageRequired: false });
      },
    };
    const now = new Date("2026-10-07T05:00:00.000Z");
    const uc = new SendMockAlertUseCase(catalog, new WazuhAdapter(), ingest as never, { record: async (e) => void audit.push(e) }, () => now);
    const r = await uc.execute({ tenantId: "ten", key: "TC-01", actor: "u1" });
    expect(r.isSuccess).toBe(true);
    expect(r.value).toMatchObject({ key: "TC-01", alertId: "alert-1", severity: "high", incidentId: "inc-1", triageRequired: false });
    expect(mockKeyOfExternalId(r.value.externalAlertId)).toBe("TC-01");
    expect(ingested).toHaveLength(1);
    expect(ingested[0]).toMatchObject({ tenantId: "ten", externalAlertId: r.value.externalAlertId });
    expect(fixture.alert.id).toBe("1727659920.20001"); // never mutated
    expect(audit).toEqual([expect.objectContaining({ action: "MOCK_ALERT_SENT", actor: "u1", entityId: "alert-1", metadata: expect.objectContaining({ key: "TC-01", file: fixture.file }) })]);
  });

  test("unknown key -> UNKNOWN_MOCK_ALERT, nothing ingested", async () => {
    const ingest = { execute: jest.fn() };
    const r = await new SendMockAlertUseCase(catalog, new WazuhAdapter(), ingest as never, { record: async () => undefined }).execute({ tenantId: "t", key: "TC-09", actor: "u" });
    expect(r.error).toBe("UNKNOWN_MOCK_ALERT");
    expect(ingest.execute).not.toHaveBeenCalled();
  });
});

describe("mock alert routes", () => {
  const fixtureCatalog: IMockAlertCatalog = { list: () => [{ ...tc("01"), alert: { secret: "payload" } }], find: () => null };
  const send = { execute: jest.fn(async () => Result.ok({ key: "TC-01", alertId: "a", externalAlertId: "mock-TC-01-1-a", severity: "medium", incidentId: null, triageRequired: true })) };
  const servers: Server[] = [];
  const start = async (enabled: boolean) => {
    const app = express();
    app.use(express.json());
    app.use("/api/v1/alerts", buildMockAlertRoutes(fixtureCatalog, send as never, enabled));
    const server = app.listen(0);
    servers.push(server);
    await new Promise<void>((r) => server.once("listening", () => r()));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1/alerts`;
  };
  const auth = (role: string) => ({ authorization: `Bearer ${signToken({ id: "u1", tenantId: "ten", role })}` });
  afterAll(() => Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r())))));
  beforeEach(() => send.execute.mockClear());

  test("GET /mock lists the catalog without payloads", async () => {
    const base = await start(true);
    const res = await fetch(`${base}/mock`, { headers: auth("IR_TEAM") });
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body).toMatchObject({ sendEnabled: true, items: [{ key: "TC-01" }] });
    expect(JSON.stringify(body)).not.toContain("payload");
  });

  test("POST send: SOC -> 201; IR_TEAM -> 403; bad key -> 404; disabled -> 403 MOCK_ALERTS_DISABLED; no token -> 401", async () => {
    const base = await start(true);
    const post = (key: string, role?: string) => fetch(`${base}/mock/${key}/send`, { method: "POST", headers: role ? auth(role) : {} });
    expect((await post("tc-01", "SOC")).status).toBe(201);
    expect(send.execute).toHaveBeenCalledWith({ tenantId: "ten", key: "TC-01", actor: "u1" });
    expect((await post("TC-01", "IR_TEAM")).status).toBe(403);
    expect((await post("..%2Fetc", "SOC")).status).toBe(404);
    expect((await post("TC-01")).status).toBe(401);
    const off = await start(false);
    const res = await fetch(`${off}/mock/TC-01/send`, { method: "POST", headers: auth("SOC") });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "MOCK_ALERTS_DISABLED" });
    expect(send.execute).toHaveBeenCalledTimes(1);
  });

  test("sending is on in dev, off in production unless MOCK_ALERTS_ENABLED=true", () => {
    expect(mockAlertSendingEnabled({ NODE_ENV: "development" })).toBe(true);
    expect(mockAlertSendingEnabled({ NODE_ENV: "production" })).toBe(false);
    expect(mockAlertSendingEnabled({ NODE_ENV: "production", MOCK_ALERTS_ENABLED: "true" })).toBe(true);
    expect(mockAlertSendingEnabled({ NODE_ENV: "development", MOCK_ALERTS_ENABLED: "false" })).toBe(false);
  });
});
