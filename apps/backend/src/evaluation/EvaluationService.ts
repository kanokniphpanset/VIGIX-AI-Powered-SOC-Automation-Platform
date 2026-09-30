/**
 * EvaluationService.ts — deterministic, backend-only evaluation of the 10 Attack Cases (§3,§5,§6,§7,§16).
 *
 * Two layers:
 *  - PURE scoring functions (evaluateCompliance / investigationSeconds / decisionSeconds) take plain inputs
 *    and contain NO I/O, so they are unit-testable and never call an LLM. The AI output is the SUBJECT being
 *    scored, never the scorer.
 *  - collectEvaluationCase() reads the REAL workflow entities from Postgres (via Prisma) and assembles the
 *    Master Evaluation Record. It never fabricates data or inserts a result.
 */
import { PrismaClient } from "@prisma/client";
import { ComplianceChecks, EvaluationCase, EvaluationSummary, VerificationMode } from "./types";
import { TcGroundTruth } from "./groundTruth";

// ---------------------------------------------------------------- PURE scoring (§16, testable, no I/O)

export interface StepInput {
  actionCode: string | null;
  target: string | null;
  requiresApproval: boolean;
}

export interface ComplianceInput {
  steps: StepInput[];
  allowedActions: string[];              // ground-truth allowed response for the attack
  knownActionCodes: Set<string>;         // Action Catalog (enabled)
  targetableValues: Set<string>;         // evidence-linked / analyst-added IOC values + affected hosts
  playbookCode: string | null;           // playbook recorded on the recommendation's snapshot
  expectedPlaybook: string;              // ground-truth expected playbook
  playbookAllowedActions: string[];      // the selected playbook's own allowed-action set
  policyByAction: Record<string, { approvalRequired: boolean; responsibleRole: string | null; approvalRole: string | null }>;
  approvalRoleUsed: string | null;       // role of the approval actually created
  approvalDecided: boolean;              // a human decision was recorded
}

/** Deterministic Recommendation Compliance — six mandatory criteria; compliant = all six (§3). */
export function evaluateCompliance(i: ComplianceInput): ComplianceChecks {
  const failed: string[] = [];
  const steps = i.steps.filter((s) => s.actionCode);
  const has = steps.length > 0;

  const attackAlignment = has && steps.every((s) => i.allowedActions.includes(s.actionCode!));
  if (!attackAlignment) failed.push(`attackAlignment: action(s) [${steps.filter((s) => !i.allowedActions.includes(s.actionCode!)).map((s) => s.actionCode).join(",") || "none"}] not in allowed set for this attack`);

  const evidenceSupport = has && steps.every((s) => !!s.target && i.targetableValues.has(s.target));
  if (!evidenceSupport) failed.push(`evidenceSupport: target(s) [${steps.filter((s) => !s.target || !i.targetableValues.has(s.target)).map((s) => s.target).join(",")}] not evidence-linked/analyst-added`);

  const knowledgeValidity = has && steps.every((s) => i.knownActionCodes.has(s.actionCode!));
  if (!knowledgeValidity) failed.push(`knowledgeValidity: action(s) [${steps.filter((s) => !i.knownActionCodes.has(s.actionCode!)).map((s) => s.actionCode).join(",")}] not in the Action Catalog`);

  const policyCompliance = has && steps.every((s) => {
    const p = i.policyByAction[s.actionCode!];
    return !!p && s.requiresApproval === p.approvalRequired && !!p.responsibleRole;
  });
  if (!policyCompliance) failed.push("policyCompliance: a step's approval flag or responsible role does not match the Policy snapshot");

  const playbookAlignment = i.playbookCode === i.expectedPlaybook && has && steps.every((s) => i.playbookAllowedActions.includes(s.actionCode!));
  if (!playbookAlignment) failed.push(`playbookAlignment: playbook ${i.playbookCode ?? "none"} != expected ${i.expectedPlaybook}, or an action is outside it`);

  const needsApproval = steps.some((s) => s.requiresApproval) || steps.some((s) => i.policyByAction[s.actionCode!]?.approvalRequired);
  const expectedRole = steps.map((s) => i.policyByAction[s.actionCode!]?.approvalRole).find((r) => !!r) ?? null;
  const approvalCorrectness = needsApproval
    ? i.approvalDecided && !!i.approvalRoleUsed && (expectedRole === null || i.approvalRoleUsed === expectedRole)
    : true;
  if (!approvalCorrectness) failed.push(`approvalCorrectness: approval role ${i.approvalRoleUsed ?? "none"} != Policy role ${expectedRole ?? "?"} (or no decision recorded)`);

  const compliant = attackAlignment && evidenceSupport && knowledgeValidity && policyCompliance && playbookAlignment && approvalCorrectness;
  return { attackAlignment, evidenceSupport, knowledgeValidity, policyCompliance, playbookAlignment, approvalCorrectness, compliant, failedChecks: failed };
}

const secondsBetween = (a: Date | null | undefined, b: Date | null | undefined): number | null =>
  a && b ? Math.round((b.getTime() - a.getTime()) / 10) / 100 : null;

/** KPI #2 — Investigation Time = T_Recommendation − T_InvestigationStart (real timestamps). */
export const investigationSeconds = (investigationStartAt: Date | null, recommendationAt: Date | null): number | null =>
  secondsBetween(investigationStartAt, recommendationAt);

/** KPI #3 — Time-to-Decision = T_Decision − T_Recommendation (real timestamps). */
export const decisionSeconds = (recommendationAt: Date | null, decisionAt: Date | null): number | null =>
  secondsBetween(recommendationAt, decisionAt);

/**
 * Verification mode (§8): a re-hunt run through CleanRehuntAdapter (or any mock forcing NO_MATCH) is MOCK and
 * must NEVER be reported as real Wazuh detection; only a re-hunt sourced from the live Wazuh indexer is REAL_WAZUH.
 */
export function verificationModeOf(wazuhIndex: string | null, evidenceSource: string | null): VerificationMode {
  if (!wazuhIndex && !evidenceSource) return "NONE";
  if (/clean-rehunt/i.test(wazuhIndex ?? "") || evidenceSource === "MOCK_REHUNT") return "MOCK";
  if (evidenceSource === "WAZUH_INDEXER") return "REAL_WAZUH";
  return "MOCK";
}

// ---------------------------------------------------------------- DB collector (real data, no fabrication)

const numField = (row: Record<string, unknown> | null, ...keys: string[]): number | null => {
  for (const k of keys) if (row && typeof row[k] === "number") return row[k] as number;
  return null;
};

export async function collectEvaluationCase(prisma: PrismaClient, gt: TcGroundTruth, knownActions: Set<string>, incidentIdOverride?: string): Promise<EvaluationCase> {
  const base: EvaluationCase = {
    caseId: gt.caseId, attackType: gt.attackType, attackName: gt.attackName, severity: null, risk: null,
    incidentId: null, alertId: null, investigationId: null, recommendationId: null, playbookCode: null, decisionId: null, responseTicketId: null, verificationId: null,
    recommendationStatus: null, compliance: null, recommendationCompliance: "NOT_EVALUATED",
    investigationStartAt: null, recommendationAt: null, decisionAt: null, investigationTimeSeconds: null, timeToDecisionSeconds: null,
    workflow: { alertIngested: false, incidentCreated: false, aiAnalysisCompleted: false, investigationCompleted: false, recommendationCreated: false, recommendationValidated: false, policyEvaluated: false, decisionCompleted: false, responseCompleted: false, verificationCompleted: false, rehuntExecuted: false },
    workflowCompleted: false, finalStatus: null,
    verificationMode: "NONE", verificationResult: null, rehuntRound: null,
    recommendationAttemptCount: 0, invalidOutputCount: 0,
    interventionRequired: false, interventionType: [], findings: [...gt.knownFindings], notes: "",
  };

  // Score a specific incident when given (repeated-run harness), else the latest one for this rule.
  const incident = incidentIdOverride
    ? await prisma.incident.findUnique({ where: { id: incidentIdOverride } })
    : await (async () => {
        const a = await prisma.alert.findFirst({ where: { siemSource: "wazuh", rawPayload: { path: ["rule", "id"], equals: gt.ruleId } }, orderBy: { receivedAt: "desc" } });
        return a ? prisma.incident.findFirst({ where: { alertId: a.id } }) : null;
      })();
  if (!incident) return base;
  const alert = incident.alertId ? await prisma.alert.findUnique({ where: { id: incident.alertId } }) : null;
  if (!alert) return base;
  base.alertId = alert.id;
  base.severity = alert.severity;
  base.workflow.alertIngested = alert.status === "received" || alert.status === "escalated";

  base.incidentId = incident.id;
  base.finalStatus = incident.status;
  base.workflow.incidentCreated = true;

  const inv1 = await prisma.investigation.findFirst({ where: { incidentId: incident.id, investigationNumber: 1 } });
  base.investigationId = inv1?.id ?? null;
  base.investigationStartAt = inv1?.startedAt?.toISOString() ?? null;
  base.workflow.investigationCompleted = inv1?.status === "COMPLETED";

  // AI analysis: real agent results for this incident (llm_analyst must be present, execution not failed).
  const agentResults = await prisma.agentResult.findMany({ where: { agentExecution: { incidentId: incident.id } }, select: { agentName: true } });
  const names = new Set(agentResults.map((a) => a.agentName));
  const lastExec = await prisma.agentExecution.findFirst({ where: { incidentId: incident.id }, orderBy: [{ completedAt: "desc" }, { startedAt: "desc" }] });
  base.workflow.aiAnalysisCompleted = names.has("llm_analyst") && !!lastExec && (lastExec.status === "SUCCESS" || lastExec.status === "PARTIAL_SUCCESS");

  const risk = await prisma.riskScore.findFirst({ where: { incidentId: incident.id }, orderBy: { id: "desc" } });
  base.risk = numField(risk as unknown as Record<string, unknown>, "score", "confidenceScore");

  // retries / invalid output
  base.invalidOutputCount = await prisma.auditLog.count({ where: { entityId: incident.id, action: "RECOMMENDATION_GENERATION_FAILED" } });

  const rec = await prisma.recommendation.findFirst({
    where: { incidentId: incident.id, status: "VALIDATED" },
    orderBy: { recommendationNumber: "desc" },
    include: { steps: { include: { action: true } }, snapshot: true },
  });
  if (!rec) {
    base.recommendationAttemptCount = base.invalidOutputCount;
    finalizeWorkflowAndIntervention(base);
    return base;
  }
  base.recommendationId = rec.id;
  base.recommendationStatus = rec.status;
  base.recommendationAt = rec.createdAt.toISOString();
  base.recommendationAttemptCount = base.invalidOutputCount + 1;
  base.workflow.recommendationCreated = true;
  base.workflow.recommendationValidated = rec.status === "VALIDATED";

  const snapshot = rec.snapshot;
  base.playbookCode = snapshot?.playbookCode ?? null;
  const policyResult = (snapshot?.policyResult ?? {}) as Record<string, { approvalRequired: boolean; responsibleRole: string | null; approvalRole: string | null }>;
  base.workflow.policyEvaluated = !!snapshot && Object.keys(policyResult).length > 0;

  // targetable values = evidence-linked IOC values + analyst-added (manual) IOC values + affected hosts
  const evidence = await prisma.evidence.findMany({ where: { investigation: { incidentId: incident.id } }, include: { iocLinks: { include: { ioc: { select: { iocValue: true } } } } } });
  const iocs = await prisma.threatIntelIoc.findMany({ where: { incidentId: incident.id }, select: { iocValue: true, createdBy: true } });
  const linked = new Set(evidence.flatMap((e) => e.iocLinks.map((l) => l.ioc.iocValue)));
  const manual = new Set(iocs.filter((i) => !!i.createdBy && i.createdBy !== "system").map((i) => i.iocValue));
  const hosts = new Set([(alert.rawPayload as any)?.agent?.name, ...evidence.map((e) => (e.structuredData as any)?.agent)].filter((h): h is string => !!h));
  const targetable = new Set<string>([...iocs.map((i) => i.iocValue).filter((v) => linked.has(v) || manual.has(v)), ...hosts]);

  // playbook's own allowed-action set (Knowledge Base)
  const pb = snapshot ? await prisma.playbook.findUnique({ where: { code: snapshot.playbookCode } }) : null;
  const pbAllowed = ((pb?.triggerConditions as any)?.allowedActions ?? []) as string[];

  // response ticket + human decision (approval)
  const plan = await prisma.responsePlan.findFirst({ where: { recommendationId: rec.id }, orderBy: { createdAt: "desc" } });
  base.responseTicketId = plan?.id ?? null;
  base.workflow.responseCompleted = plan?.status === "COMPLETED";
  const approval = plan ? await prisma.approval.findFirst({ where: { responseId: plan.id }, orderBy: { createdAt: "desc" } }) : null;
  base.decisionId = approval?.id ?? null;
  base.decisionAt = approval?.decidedAt?.toISOString() ?? null;
  base.workflow.decisionCompleted = !!approval && (approval.status === "approved" || approval.status === "rejected") && !!approval.decidedAt;

  // verification / re-hunt
  const verification = plan ? await prisma.verification.findFirst({ where: { responseId: plan.id } }) : null;
  base.verificationId = verification?.id ?? null;
  base.verificationResult = verification?.result ?? null;
  base.workflow.verificationCompleted = !!verification?.result;
  base.workflow.rehuntExecuted = !!verification;
  if (verification) {
    const idx = verification.wazuhIndex ?? "";
    const src = (verification.afterState as any)?.evidenceSource ?? "";
    base.verificationMode = verificationModeOf(idx, src);
    const m = /#round-(\d+)/.exec(idx);
    base.rehuntRound = m ? Number(m[1]) : 1;
  }

  // KPI timings (real timestamps)
  base.investigationTimeSeconds = investigationSeconds(inv1?.startedAt ?? null, rec.createdAt);
  base.timeToDecisionSeconds = decisionSeconds(rec.createdAt, approval?.decidedAt ?? null);

  // compliance (deterministic)
  const compliance = evaluateCompliance({
    steps: rec.steps.filter((s) => s.actionId).map((s) => ({ actionCode: s.action?.code ?? null, target: s.target, requiresApproval: s.requiresApproval })),
    allowedActions: gt.allowedActions,
    knownActionCodes: knownActions,
    targetableValues: targetable,
    playbookCode: snapshot?.playbookCode ?? null,
    expectedPlaybook: gt.expectedPlaybook,
    playbookAllowedActions: pbAllowed,
    policyByAction: policyResult,
    approvalRoleUsed: approval?.approvalRole ?? null,
    approvalDecided: base.workflow.decisionCompleted,
  });
  base.compliance = compliance;
  base.recommendationCompliance = compliance.compliant ? "COMPLIANT" : "NON_COMPLIANT";
  if (!compliance.compliant) base.notes = compliance.failedChecks.join(" | ");

  finalizeWorkflowAndIntervention(base);
  return base;
}

function finalizeWorkflowAndIntervention(c: EvaluationCase): void {
  const w = c.workflow;
  c.workflowCompleted = w.alertIngested && w.incidentCreated && w.aiAnalysisCompleted && w.recommendationCreated && w.recommendationValidated && w.policyEvaluated && w.decisionCompleted && w.responseCompleted && w.verificationCompleted && w.rehuntExecuted;
  const types = new Set(c.interventionType);
  if (c.invalidOutputCount > 0) types.add("RECOMMENDATION_RETRY");
  if (c.findings.some((f) => /manual|analyst|promoted|added a COMMAND|EMAIL IOC/i.test(f))) types.add("ANALYST_ADDED_IOC");
  if (c.findings.some((f) => /seeded|catalog|KB gap|playbook was/i.test(f))) types.add("SYSTEM_KB_UPDATED");
  c.interventionType = [...types];
  // An intervention is a change that had to be made during the run (manual IOC, KB/seed fix, retry).
  // A ground-truth documentation note (e.g. a technique->playbook mapping choice) is a finding, not an intervention.
  c.interventionRequired = c.interventionType.length > 0;
}

// ---------------------------------------------------------------- summary (§12)

const stats = (xs: (number | null)[]) => {
  const v = xs.filter((x): x is number => x !== null);
  if (!v.length) return { min: null, max: null, avg: null };
  return { min: Math.min(...v), max: Math.max(...v), avg: Math.round((v.reduce((a, b) => a + b, 0) / v.length) * 100) / 100 };
};

export function summarize(cases: EvaluationCase[]): EvaluationSummary {
  const evaluated = cases.filter((c) => c.recommendationCompliance !== "NOT_EVALUATED");
  const compliant = evaluated.filter((c) => c.recommendationCompliance === "COMPLIANT").length;
  const automaticCompliant = evaluated.filter((c) => c.recommendationCompliance === "COMPLIANT" && !c.interventionRequired).length;
  const it = stats(cases.map((c) => c.investigationTimeSeconds));
  const dt = stats(cases.map((c) => c.timeToDecisionSeconds));
  return {
    totalCases: cases.length,
    evaluatedCases: evaluated.length,
    compliantRecommendations: compliant,
    nonCompliantRecommendations: evaluated.length - compliant,
    recommendationComplianceRate: evaluated.length ? Math.round((compliant / evaluated.length) * 10000) / 100 : 0,
    automaticCompliant,
    complianceRateAutomatic: evaluated.length ? Math.round((automaticCompliant / evaluated.length) * 10000) / 100 : 0,
    investigationTimeMin: it.min, investigationTimeMax: it.max, investigationTimeAverage: it.avg,
    decisionTimeMin: dt.min, decisionTimeMax: dt.max, decisionTimeAverage: dt.avg,
    workflowCompletedCases: cases.filter((c) => c.workflowCompleted).length,
    interventionCases: cases.filter((c) => c.interventionRequired).length,
    mockVerificationCases: cases.filter((c) => c.verificationMode === "MOCK").length,
    realWazuhVerificationCases: cases.filter((c) => c.verificationMode === "REAL_WAZUH").length,
  };
}

export async function knownActionCodes(prisma: PrismaClient): Promise<Set<string>> {
  const rows = await prisma.action.findMany({ where: { enabled: true }, select: { code: true } });
  return new Set(rows.map((r) => r.code));
}
