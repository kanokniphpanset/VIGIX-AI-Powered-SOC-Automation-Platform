import express from "express";
import { createHmac } from "node:crypto";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { buildWebhookRoutes } from "../src/presentation/http/routes/webhook.routes";
import { keepRawBody } from "../src/presentation/http/middlewares/webhookAuth.middleware";
import { SiemInboundWebhookController } from "../src/presentation/http/webhooks/siem-inbound.webhook";
import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";

/**
 * Wazuh → VIGIX: the Wazuh manager's custom-vigix integration POSTs each alert to /api/v1/webhooks/siem/wazuh,
 * signed with HMAC-SHA256 over the raw body (X-Webhook-Signature: sha256=<hex>). Only correctly signed alerts
 * reach the Alert Inbox. Real routes + middleware + controller + WazuhAdapter; the ingest use case is recorded.
 */

const SECRET = "test-siem-secret";
const ingested: Record<string, unknown>[] = [];
const ingest = {
  execute: async (input: Record<string, unknown>) => {
    ingested.push(input);
    return { value: { alert: { id: "alert-1", status: "NEW" }, incidentId: null, aiJob: null, duplicate: false, triageRequired: true } };
  },
};
const controller = new SiemInboundWebhookController(ingest as never, { wazuh: new WazuhAdapter() });

let server: Server;
let base = "";
const prevSecret = process.env.SIEM_WEBHOOK_SECRET;
beforeAll(async () => {
  const app = express();
  app.use(express.json({ verify: keepRawBody }));
  app.use("/api/v1/webhooks", buildWebhookRoutes(controller, { handle: (_q: unknown, r: express.Response) => r.end() } as never));
  server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => {
  process.env.SIEM_WEBHOOK_SECRET = prevSecret;
  return new Promise<void>((r) => server.close(() => r()));
});
beforeEach(() => {
  process.env.SIEM_WEBHOOK_SECRET = SECRET;
  ingested.length = 0;
});

// A real Wazuh alert shape (rule 5763, sshd brute force, from the lab agent).
const alert = {
  id: "1790000000.123456",
  timestamp: "2026-09-27T10:00:00.000+0000",
  rule: { id: "5763", level: 10, description: "sshd: brute force trying to get access to the system. Authentication failed.", groups: ["syslog", "sshd", "authentication_failures"], mitre: { id: ["T1110"], tactic: ["Credential Access"], technique: ["Brute Force"] } },
  agent: { id: "001", name: "vigix-lab-ubuntu", ip: "172.31.250.10" },
  data: { srcip: "172.31.250.20", dstuser: "root" },
  full_log: "Sep 27 10:00:00 vigix-lab-ubuntu sshd[123]: Failed password for root from 172.31.250.20 port 40000 ssh2",
};
const sign = (body: string, secret = SECRET) => `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
const post = async (body: string, signature?: string) => {
  const res = await fetch(`${base}/api/v1/webhooks/siem/wazuh`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(signature ? { "x-webhook-signature": signature } : {}) },
    body,
  });
  return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> };
};

it("a correctly signed Wazuh alert is accepted (202) and ingested with severity from rule.level", async () => {
  const body = JSON.stringify(alert);
  const r = await post(body, sign(body));
  expect(r).toEqual({ status: 202, body: expect.objectContaining({ alertId: "alert-1", duplicate: false, triageRequired: true }) });
  expect(ingested).toEqual([expect.objectContaining({ externalAlertId: "1790000000.123456", siemSource: "wazuh", severity: "medium", rawPayload: alert })]);
});

it("no signature -> 401, nothing ingested", async () => {
  expect((await post(JSON.stringify(alert))).status).toBe(401);
  expect(ingested).toEqual([]);
});

it("signed with the wrong secret -> 401", async () => {
  const body = JSON.stringify(alert);
  expect((await post(body, sign(body, "not-the-secret"))).status).toBe(401);
  expect(ingested).toEqual([]);
});

it("body changed after signing -> 401 (signature is over the exact bytes sent)", async () => {
  const signature = sign(JSON.stringify(alert));
  const tampered = JSON.stringify({ ...alert, rule: { ...alert.rule, level: 15 } });
  expect((await post(tampered, signature)).status).toBe(401);
  expect(ingested).toEqual([]);
});

it("malformed signature header -> 401", async () => {
  expect((await post(JSON.stringify(alert), "sha256=zz")).status).toBe(401);
  expect((await post(JSON.stringify(alert), SECRET)).status).toBe(401);
  expect(ingested).toEqual([]);
});

it("no SIEM_WEBHOOK_SECRET on the server -> 500 (fails closed, never accepts unsigned alerts)", async () => {
  delete process.env.SIEM_WEBHOOK_SECRET;
  const body = JSON.stringify(alert);
  expect((await post(body, sign(body))).status).toBe(500);
  expect(ingested).toEqual([]);
});
