/**
 * order-experiment.ts — DIAGNOSTIC (not an evaluation KPI): does the ORDER of the IP candidates in the recommendation
 * context decide which IP the LLM picks for ACT-BLOCK-DESTINATION-IP? The context of an incident is built from the DB,
 * then (a) used as built, (b) with every IP-only `targets` list and the `iocs` list REVERSED. Nothing else changes.
 * The real LlmRecommendationAgent + RecommendationValidator are used; nothing is persisted. The pick is classified by
 * role against the alert's srcip/dstip. Usage: EVAL_DB=soar_ext_eval . scripts/eval/eval-env.sh && EVAL_ADD_DB=soar_ext_eval \
 *   npx ts-node --transpile-only scripts/eval/extended/order-experiment.ts <incidentId:TC-07> <incidentId:TC-09> [--reps 5]
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { buildPipeline, TENANT } from "../additional/common";

const IP = /^\d{1,3}(\.\d{1,3}){3}$/;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const reps = Number(process.argv[process.argv.indexOf("--reps") + 1] || 5);

function reverseIps(ctx: any) {
  const c = JSON.parse(JSON.stringify(ctx));
  let swappedLists = 0;
  const walk = (o: any) => {
    if (Array.isArray(o)) { o.forEach(walk); return; }
    if (o && typeof o === "object") {
      for (const [k, v] of Object.entries(o)) {
        if (k === "targets" && Array.isArray(v) && v.length > 1 && v.every((x) => typeof x === "string" && IP.test(x))) { (o as any)[k] = [...v].reverse(); swappedLists++; }
        else walk(v);
      }
    }
  };
  walk(c);
  if (Array.isArray(c.iocs)) c.iocs = [...c.iocs].reverse();
  return { ctx: c, swappedLists };
}

(async () => {
  const ids = process.argv.slice(2).filter((a) => /^[0-9a-f-]{36}$/.test(a));
  const prisma = new PrismaClient();
  const P = buildPipeline(prisma, process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8001", { firstRound: true });
  const out: any[] = [];
  const actionCode = new Map((await prisma.action.findMany({ select: { id: true, code: true } })).map((x) => [x.id, x.code]));
  for (const incidentId of ids) {
    const a = (await prisma.$queryRawUnsafe<any[]>(`select a.raw_payload->'data'->>'srcip' s, a.raw_payload->'data'->>'dstip' d from alerts a join incident_alerts ia on ia.alert_id::text = a.id::text where ia.incident_id::text = $1 limit 1`, incidentId))[0];
    const built = await P.builder.build(incidentId, TENANT);
    if (built.isFailure) throw new Error(JSON.stringify(built.error));
    const asBuilt = built.value;
    const variants: Record<string, any> = { as_built: asBuilt, ips_reversed: reverseIps(asBuilt).ctx };
    const firstTarget = (c: any) => JSON.stringify((JSON.stringify(c).match(/"targets":\[("[\d.]+",?)+\]/) ?? [""])[0]);
    for (const [name, ctx] of Object.entries(variants)) {
      const picks: any[] = [];
      for (let r = 1; r <= reps; r++) {
        for (let attempt = 0; attempt < 6; attempt++) {
          try {
            const cand = await (P.agent as any).generate(ctx, null);
            const v = await P.validator.validate(cand, ctx, TENANT);
            const steps: any[] = ((v as any).steps ?? []);
            const dest = steps.find((s: any) => /DESTINATION-IP/.test(actionCode.get(s.actionId) ?? ""));
            const target = dest?.target ?? null;
            picks.push({ rep: r, validated: (v as any).status ?? null, destinationIpTarget: target, role: target === a.d ? "destination (correct)" : target === a.s ? "source (wrong)" : target ? "other" : "no destination-IP step" });
            console.log(`${incidentId.slice(0, 8)} ${name} #${r}: ${target} → ${picks[picks.length - 1].role}`);
            break;
          } catch (e) { console.log(`   infra/agent error, retry: ${String((e as Error).message).slice(0, 80)}`); await sleep(20000); }
        }
      }
      out.push({ incidentId, srcip: a.s, dstip: a.d, variant: name, targetsListInContext: firstTarget(ctx), picks, correct: picks.filter((p) => p.role.startsWith("destination")).length, of: picks.length });
    }
  }
  const f = path.join(__dirname, "..", "..", "..", "..", "..", "results", "extended-evaluation", "data", "order-experiment.json");
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify({ at: new Date().toISOString(), note: "diagnostic: only the order of IP candidates in the context differs between variants", results: out }, null, 2));
  console.log("wrote", f);
  await prisma.$disconnect();
})();
