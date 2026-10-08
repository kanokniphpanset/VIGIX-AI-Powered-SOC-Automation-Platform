/**
 * verifyWazuhRealFixtures.ts - READ-ONLY check that test/fixtures/wazuh-real/*.json are still byte-for-byte the alerts
 * they were captured from. For each entry of _index.json it GETs that exact Indexer document (index + _id), drops the
 * Indexer-added @timestamp, applies the masks, and compares with the committed fixture.
 *
 *   WAZUH_INDEXER_URL=https://localhost:9200 WAZUH_INDEXER_USERNAME=... WAZUH_INDEXER_PASSWORD=... \
 *   WAZUH_INDEXER_CA_PATH=... WAZUH_INDEXER_TLS_SERVERNAME=wazuh.indexer \
 *   WAZUH_FIXTURE_MASKS='<real-name>=labuser,<real-host>=WIN-LAB01' \
 *   npx ts-node --transpile-only scripts/verifyWazuhRealFixtures.ts
 *
 * Only GET /<index>/_doc/<id>. Credentials come from the environment, are never printed, and nothing is written. The mask
 * pairs are given at run time so the real user/host names are not stored in the repository.
 */
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";

const DIR = path.resolve(__dirname, "../test/fixtures/wazuh-real");
const env = process.env;
if (!env.WAZUH_INDEXER_URL || !env.WAZUH_INDEXER_USERNAME || !env.WAZUH_INDEXER_PASSWORD) {
  console.log("SKIP: WAZUH_INDEXER_URL / USERNAME / PASSWORD are not set.");
  process.exit(0);
}
const masks = (env.WAZUH_FIXTURE_MASKS ?? "").split(",").filter(Boolean).map((p) => p.split("=") as [string, string]);
const mask = (v: unknown): unknown =>
  typeof v === "string" ? masks.reduce((s, [from, to]) => s.split(from).join(to), v)
  : Array.isArray(v) ? v.map(mask)
  : v && typeof v === "object" ? Object.fromEntries(Object.entries(v as object).map(([k, x]) => [k, mask(x)]))
  : v;

function get(pathname: string): Promise<{ status: number; body: any }> {
  const url = new URL(pathname, env.WAZUH_INDEXER_URL);
  const auth = Buffer.from(`${env.WAZUH_INDEXER_USERNAME}:${env.WAZUH_INDEXER_PASSWORD}`).toString("base64");
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: "GET", hostname: url.hostname, port: url.port || 443, path: url.pathname,
        headers: { Authorization: `Basic ${auth}`, Accept: "application/json" },
        ca: env.WAZUH_INDEXER_CA_PATH ? fs.readFileSync(env.WAZUH_INDEXER_CA_PATH) : undefined,
        servername: env.WAZUH_INDEXER_TLS_SERVERNAME || undefined,
        rejectUnauthorized: env.WAZUH_INDEXER_INSECURE_TLS !== "true", timeout: 15000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => { try { resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }); } catch (e) { reject(e); } });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.end();
  });
}

(async () => {
  const index = JSON.parse(fs.readFileSync(path.join(DIR, "_index.json"), "utf8")) as Record<string, { indexerRef: { index: string; docId: string } }>;
  let bad = 0;
  for (const [file, { indexerRef }] of Object.entries(index).sort()) {
    const local = JSON.parse(fs.readFileSync(path.join(DIR, file), "utf8"));
    try {
      const r = await get(`/${encodeURIComponent(indexerRef.index)}/_doc/${encodeURIComponent(indexerRef.docId)}`);
      if (r.status !== 200 || !r.body?._source) { console.log(`MISSING ${file} (HTTP ${r.status})`); bad++; continue; }
      const { "@timestamp": _drop, ...source } = r.body._source;
      const same = isDeepStrictEqual(mask(source), local);
      console.log(`${same ? "OK     " : "DIFF   "} ${file}`);
      if (!same) bad++;
    } catch (e) {
      console.log(`ERROR  ${file}: ${e instanceof Error ? e.message : e}`);
      bad++;
    }
  }
  console.log(bad ? `${bad} fixture(s) differ from the Indexer` : "all fixtures match their Indexer documents");
  process.exit(bad ? 1 : 0);
})();
