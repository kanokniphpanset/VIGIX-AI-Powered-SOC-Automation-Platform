/**
 * demo-real-rehunt.ts — proves the REAL re-hunt path (verificationMode REAL_WAZUH) against the live Wazuh
 * indexer, as opposed to the CleanRehuntAdapter (MOCK, forced NO_MATCH) used to walk the synthetic TC flow.
 *
 * It uses the same provider the backend wires when REHUNT_PROVIDER=wazuh (createRehuntProvider), queries a
 * real IOC taken from a genuine `attack-endpoint` alert, and reports the live result. Requires the single-node
 * Wazuh stack up and WAZUH_INDEXER_URL/USERNAME/PASSWORD set in apps/backend/.env.
 *
 *   npx ts-node --transpile-only scripts/demo-real-rehunt.ts
 */
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { createRehuntProvider } from "../src/infrastructure/external-services/siem/createRehuntProvider";

(async () => {
  const p = new PrismaClient();
  const provider = createRehuntProvider(process.env);
  console.log("provider:", provider.constructor.name, "| configured:", provider.isConfigured());
  console.log("health:", JSON.stringify(await provider.health()));

  // real IOC from a genuine attack-endpoint alert (produced by the live Ubuntu box, not a mock)
  const rows = await p.alert.findMany({ where: { siemSource: "wazuh", rawPayload: { path: ["agent", "name"], equals: "attack-endpoint" } }, orderBy: { receivedAt: "desc" }, take: 100 });
  let picked: any = null, ip: string | null = null;
  for (const a of rows) { const rp: any = a.rawPayload; const s = rp?.data?.srcip ?? rp?.srcip; if (s && /\d+\.\d+\.\d+\.\d+/.test(String(s))) { picked = rp; ip = String(s); break; } }
  if (!ip) { console.log("No attack-endpoint alert with a routable/loopback srcip found — run infra/docker/attack-endpoint/run.sh attack first."); await p.$disconnect(); return; }
  console.log(`\nreal IOC: ip=${ip} (from rule ${picked?.rule?.id} - ${String(picked?.rule?.description).slice(0, 60)})`);

  const res = await provider.rehunt({
    incidentId: "demo-real-rehunt", responseId: "demo-real-rehunt",
    hosts: ["attack-endpoint"], iocs: [{ type: "ip", value: ip }],
    rule: picked?.rule?.id ? { id: String(picked.rule.id), description: picked?.rule?.description } : undefined,
    timeRange: { start: new Date(Date.now() - 21 * 24 * 3600 * 1000), end: new Date() }, investigationNumber: 1,
  });

  console.log("\n=== REAL WAZUH RE-HUNT (verificationMode = REAL_WAZUH) ===");
  console.log(`source: ${res.source}`);
  console.log(`matchingEvents: ${res.matchingEvents}`);
  console.log(`affectedHosts: ${JSON.stringify(res.affectedHosts)}`);
  console.log(`iocRecurrence: ${res.iocRecurrence} | spreadDetected: ${res.spreadDetected} | threatContained: ${res.threatContained}`);
  console.log(`index: ${res.index}`);
  await p.$disconnect();
})().catch((e) => { console.error("real re-hunt error:", String(e?.stack ?? e).slice(0, 500)); process.exit(2); });
