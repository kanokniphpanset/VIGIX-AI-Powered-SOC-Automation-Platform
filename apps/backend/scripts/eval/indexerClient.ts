/**
 * indexerClient.ts — read-only client for the Wazuh Indexer, used by the evaluation runner to fetch the REAL
 * alert an endpoint action produced (the same document the manager's custom-vigix integration forwarded).
 * Credentials come from the process environment only; nothing is ever written to the indexer.
 */
import https from "node:https";
import fs from "node:fs";

function request(method: "GET" | "POST", path: string, body?: unknown): Promise<{ status: number; body: any }> {
  const base = new URL(process.env.WAZUH_INDEXER_URL ?? "https://localhost:9200");
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const auth = Buffer.from(`${process.env.WAZUH_INDEXER_USERNAME}:${process.env.WAZUH_INDEXER_PASSWORD}`).toString("base64");
  return new Promise((resolve, reject) => {
    const req = https.request({
      method, hostname: base.hostname, port: base.port || 443, path,
      headers: { Authorization: `Basic ${auth}`, Accept: "application/json", ...(payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {}) },
      ca: process.env.WAZUH_INDEXER_CA_PATH ? fs.readFileSync(process.env.WAZUH_INDEXER_CA_PATH) : undefined,
      servername: process.env.WAZUH_INDEXER_TLS_SERVERNAME || undefined,
      rejectUnauthorized: process.env.WAZUH_INDEXER_INSECURE_TLS !== "true", timeout: 20000,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => { const t = Buffer.concat(chunks).toString("utf8"); try { resolve({ status: res.statusCode ?? 0, body: t ? JSON.parse(t) : null }); } catch { resolve({ status: res.statusCode ?? 0, body: null }); } });
    });
    req.on("timeout", () => req.destroy(new Error("indexer timeout")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

export interface FoundAlert { docId: string; source: Record<string, any> }

/** Earliest alert of `ruleId` raised by `agentName` at/after `since` (ISO). Polls until found or `waitMs` elapses. */
export async function waitForAlert(agentName: string, ruleId: string, since: string, waitMs = 150000): Promise<FoundAlert | null> {
  const deadline = Date.now() + waitMs;
  const index = encodeURIComponent(process.env.WAZUH_INDEXER_INDEX_PATTERN || process.env.WAZUH_INDEX_PATTERN || "wazuh-alerts-4.x-*");
  while (Date.now() < deadline) {
    const res = await request("POST", `/${index}/_search`, {
      size: 1, sort: [{ timestamp: { order: "asc", unmapped_type: "date" } }],
      query: { bool: { filter: [{ term: { "agent.name": agentName } }, { term: { "rule.id": ruleId } }, { range: { timestamp: { gte: since } } }] } },
    });
    const hit = res.body?.hits?.hits?.[0];
    if (res.status === 200 && hit) return { docId: hit._id, source: hit._source };
    await new Promise((r) => setTimeout(r, 4000));
  }
  return null;
}
