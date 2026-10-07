/** indexer.ts — read-only Wazuh Indexer helpers for the EXTENDED evaluation (same credentials/TLS handling as ../indexerClient.ts). */
import https from "node:https";
import fs from "node:fs";

export function indexerSearch(body: unknown): Promise<any> {
  const base = new URL(process.env.WAZUH_INDEXER_URL ?? "https://localhost:9200");
  const payload = JSON.stringify(body);
  const auth = Buffer.from(`${process.env.WAZUH_INDEXER_USERNAME}:${process.env.WAZUH_INDEXER_PASSWORD}`).toString("base64");
  const index = encodeURIComponent(process.env.WAZUH_INDEXER_INDEX_PATTERN || process.env.WAZUH_INDEX_PATTERN || "wazuh-alerts-4.x-*");
  return new Promise((resolve, reject) => {
    const req = https.request({
      method: "POST", hostname: base.hostname, port: base.port || 443, path: `/${index}/_search`,
      headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
      ca: process.env.WAZUH_INDEXER_CA_PATH ? fs.readFileSync(process.env.WAZUH_INDEXER_CA_PATH) : undefined,
      servername: process.env.WAZUH_INDEXER_TLS_SERVERNAME || undefined, rejectUnauthorized: process.env.WAZUH_INDEXER_INSECURE_TLS !== "true", timeout: 20000,
    }, (res) => { const c: Buffer[] = []; res.on("data", (d: Buffer) => c.push(d)); res.on("end", () => { try { resolve(JSON.parse(Buffer.concat(c).toString("utf8"))); } catch (e) { reject(e); } }); });
    req.on("error", reject); req.write(payload); req.end();
  });
}

/** All alerts raised by `agent` since `since` (ISO), oldest first. */
export async function alertsSince(agent: string, since: string, size = 200): Promise<{ docId: string; src: any }[]> {
  const r = await indexerSearch({ size, sort: [{ timestamp: { order: "asc", unmapped_type: "date" } }], query: { bool: { filter: [{ term: { "agent.name": agent } }, { range: { timestamp: { gte: since } } }] } } });
  return (r?.hits?.hits ?? []).map((h: any) => ({ docId: h._id, src: h._source }));
}
