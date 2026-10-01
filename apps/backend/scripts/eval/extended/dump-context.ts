/** dump-context.ts — diagnostic: writes the recommendation context (what the LLM is given) of one incident to a JSON file. Read-only. */
import * as fs from "node:fs";
import { PrismaClient } from "@prisma/client";
import { buildPipeline, TENANT } from "../additional/common";
(async () => {
  const [incidentId, out] = process.argv.slice(2);
  const prisma = new PrismaClient();
  const P = buildPipeline(prisma, process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8001", { firstRound: true });
  const r = await P.builder.build(incidentId, TENANT);
  if (r.isFailure) throw new Error(JSON.stringify(r.error));
  fs.writeFileSync(out, JSON.stringify(r.value, null, 1));
  console.log("wrote", out, JSON.stringify(r.value).length, "bytes");
  await prisma.$disconnect();
})();
