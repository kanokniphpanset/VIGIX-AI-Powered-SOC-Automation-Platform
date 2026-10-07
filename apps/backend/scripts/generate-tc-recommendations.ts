/**
 * One-off: generate a PERSISTED Recommendation for each incident opened by the
 * TC-01..TC-10 mocks, using the same real use case + wiring the e2e runner uses
 * (RecommendationContextBuilder -> LlmRecommendationAgent -> RecommendationValidator
 * -> PrismaRecommendationRepository). In-process, no JWT. Notifications are no-op.
 *
 *   npx ts-node --transpile-only scripts/generate-tc-recommendations.ts
 */
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaRecommendationContextRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { PrismaActionRepository } from "../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { PrismaRunbookRepository } from "../src/infrastructure/database/postgres/repositories/RunbookRepository.prisma";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaRecommendationRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { PrismaApprovalRepository } from "../src/infrastructure/database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaPolicyRepository } from "../src/infrastructure/database/postgres/repositories/PolicyRepository.prisma";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { ApprovalService } from "../src/application/approval/services/ApprovalService";
import { ResourceAssetCriticalityProvider } from "../src/infrastructure/assets/ResourceAssetCriticalityProvider";
import { RecommendationContextBuilder } from "../src/application/recommendation/services/RecommendationContextBuilder";
import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { RecommendationValidator } from "../src/infrastructure/recommendation-validation/RecommendationValidator";
import { LlmRecommendationAgent } from "../src/infrastructure/ai/LlmRecommendationAgent";
import { INotificationDispatcherPort } from "../src/application/notification/ports/INotificationDispatcherPort";

const AI_URL = process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8000";
const RULE_IDS = ["100200", "100300", "100301", "100320", "100340", "100350"];

(async () => {
  const prisma = new PrismaClient();
  const noNotify = { emit: async () => undefined } as unknown as INotificationDispatcherPort;
  const ctxRepo = new PrismaRecommendationContextRepository(prisma);
  const actions = new PrismaActionRepository(prisma);
  const runbooks = new PrismaRunbookRepository(prisma);
  const playbookRepo = new PrismaPlaybookRepository(prisma);
  const recs = new PrismaRecommendationRepository(prisma);
  const approvals = new PrismaApprovalRepository(prisma);
  const audit = new AuditLogger(prisma);
  const policy = new PolicyEvaluator(new PrismaPolicyRepository(prisma));
  const approvalService = new ApprovalService(ctxRepo, actions, policy, approvals, audit, noNotify, "http://localhost", new ResourceAssetCriticalityProvider());
  const generate = new GenerateRecommendationUseCase(
    new RecommendationContextBuilder(ctxRepo, actions, runbooks, playbookRepo, approvalService),
    new LlmRecommendationAgent(AI_URL),
    "LlmRecommendationAgent/v2.0.0",
    new RecommendationValidator(actions, runbooks),
    recs,
    audit
  );

  const since = new Date(Date.now() - 120 * 60 * 1000);
  const rows = await prisma.incident.findMany({ where: { openedAt: { gt: since } }, include: { alert: true }, orderBy: { openedAt: "asc" } });
  const targets = rows.filter((i) => RULE_IDS.includes(((i.alert?.rawPayload as any)?.rule?.id) ?? ""));
  console.log(`AI_URL=${AI_URL} — generating recommendations for ${targets.length} incident(s)\n`);

  const recRows = (id: string) => prisma.recommendation.findMany({ where: { incidentId: id }, orderBy: { recommendationNumber: "asc" }, include: { steps: true } });

  for (const inc of targets) {
    const rule = (inc.alert?.rawPayload as any)?.rule?.id;
    const host = (inc.alert?.rawPayload as any)?.agent?.name;
    const cycle = inc.investigationNumber ?? 1;
    const usable = async () => {
      const latest = (await recRows(inc.id)).filter((r) => r.status === "VALIDATED").pop();
      return !!latest && latest.investigationNumber === cycle && latest.steps.some((s) => s.actionId);
    };
    let last = "";
    for (let attempt = 0; attempt < 3 && !(await usable()); attempt++) {
      const g = await generate.execute({ incidentId: inc.id, tenantId: inc.tenantId });
      last = g.isSuccess ? "VALIDATED" : `FAIL(${JSON.stringify((g as any).error)})`;
    }
    const validated = (await recRows(inc.id)).filter((r) => r.status === "VALIDATED").pop();
    const steps = validated?.steps.filter((s) => s.actionId).map((s) => `${(s as any).objective ?? "step"}`) ?? [];
    console.log(`rule ${String(rule).padEnd(6)} (${String(host).padEnd(11)}) -> ${validated ? `VALIDATED #${validated.recommendationNumber}, ${steps.length} action step(s)` : `no valid rec (${last})`}`);
  }

  console.log("\n--- final recommendation counts ---");
  for (const inc of targets) {
    const rule = (inc.alert?.rawPayload as any)?.rule?.id;
    const all = await recRows(inc.id);
    const v = all.filter((r) => r.status === "VALIDATED");
    console.log(`rule ${String(rule).padEnd(6)}: total ${all.length}, VALIDATED ${v.length}, steps ${v.reduce((n, r) => n + r.steps.length, 0)}`);
  }
  await prisma.$disconnect();
})().catch((e) => { console.error("crashed:", String(e?.stack ?? e).slice(0, 600)); process.exit(2); });
