/**
 * One-off: re-run AI analysis for the incidents opened by the TC-01..TC-10 mock
 * alerts, whose first analysis FAILED because the AI orchestrator (:8000) was
 * down. Wires the same real use case the HTTP route and e2e runner use and
 * calls it in-process (no JWT needed). Safe to re-run; the run guard gates it.
 *
 *   npx ts-node --transpile-only scripts/retrigger-tc-ai.ts
 */
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaIncidentRepository } from "../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { PrismaInvestigationRepository } from "../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma";
import { PrismaRecommendationContextRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { PrismaAiAnalysisRunGuard } from "../src/infrastructure/database/postgres/repositories/AiAnalysisRunGuard.prisma";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { LangGraphOrchestratorAdapter } from "../src/infrastructure/ai/LangGraphOrchestratorAdapter";
import { RunIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/RunIncidentAiAnalysis.usecase";
import { GetIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/GetIncidentAiAnalysis.usecase";

const AI_URL = process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8000";
const ACTOR = "tc-eval-reanalyze";

(async () => {
  const prisma = new PrismaClient();
  const incidents = new PrismaIncidentRepository(prisma);
  const investigations = new PrismaInvestigationRepository(prisma);
  const ctxRepo = new PrismaRecommendationContextRepository(prisma);
  const audit = new AuditLogger(prisma);
  const run = new RunIncidentAiAnalysisUseCase(
    incidents,
    new PrismaAiAnalysisRunGuard(prisma),
    new LangGraphOrchestratorAdapter(AI_URL),
    investigations,
    new GetIncidentAiAnalysisUseCase(ctxRepo),
    audit
  );

  // Incidents opened by the TC mocks (last 90 min). rule ids the 6 escalations used.
  const RULE_IDS = ["100200", "100300", "100301", "100320", "100340", "100350"];
  const since = new Date(Date.now() - 90 * 60 * 1000);
  const rows = await prisma.incident.findMany({
    where: { openedAt: { gt: since } },
    orderBy: { openedAt: "asc" },
    include: { alert: true },
  });
  const targets = rows.filter((i) => RULE_IDS.includes(((i.alert?.rawPayload as any)?.rule?.id) ?? ""));
  console.log(`AI_URL=${AI_URL} — re-running analysis for ${targets.length} incident(s)\n`);

  for (const inc of targets) {
    const rule = (inc.alert?.rawPayload as any)?.rule?.id;
    const host = (inc.alert?.rawPayload as any)?.agent?.name;
    process.stdout.write(`rule ${rule} (${host}) ${inc.id.slice(0, 8)} ... `);
    try {
      const r = await run.execute({ tenantId: inc.tenantId, incidentId: inc.id, actor: ACTOR });
      console.log(r.isSuccess ? "OK" : `FAIL: ${JSON.stringify((r as any).error)}`);
    } catch (e) {
      console.log(`THREW: ${String((e as Error).message).slice(0, 120)}`);
    }
  }

  // Report what landed.
  console.log("\n--- result ---");
  for (const inc of targets) {
    const agents = await prisma.agentResult.findMany({ where: { agentExecution: { incidentId: inc.id } }, select: { agentName: true } });
    const execs = await prisma.agentExecution.findMany({ where: { incidentId: inc.id }, select: { status: true }, orderBy: { id: "desc" }, take: 1 });
    const recs = await prisma.recommendation.count({ where: { incidentId: inc.id } });
    const rule = (inc.alert?.rawPayload as any)?.rule?.id;
    console.log(`rule ${rule}: exec=${execs[0]?.status ?? "?"} | agents=[${[...new Set(agents.map((a) => a.agentName))].join(",") || "none"}] | recs=${recs}`);
  }
  await prisma.$disconnect();
})().catch((e) => { console.error("crashed:", e); process.exit(2); });
