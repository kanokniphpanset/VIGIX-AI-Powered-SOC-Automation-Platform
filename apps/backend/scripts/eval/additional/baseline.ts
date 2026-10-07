/**
 * baseline.ts — Evaluation A: CONTROLLED PROCEDURAL BASELINE.
 *
 * NOT a human study and NOT a claim about analyst performance. It is a deterministic, non-AI procedure that performs
 * the same stages VIGIX does, without the AI analysis / recommendation step:
 *
 *   Alert -> Evidence Collection -> Investigation -> Manual Response Plan -> (Decision)
 *
 *  1. Evidence collection: read the SAME Wazuh alert from the Wazuh Indexer and extract indicators with the SAME
 *     deterministic extractor VIGIX uses (`extractAlertIocs`); no AI extraction, no CTI, no RAG.
 *  2. Investigation: MITRE techniques declared by the alert -> playbook via the SAME `PlaybookSelector`
 *     (no AI-inferred techniques).
 *  3. Response plan: "static playbook lookup" — for every containment action the selected playbook allows AND the
 *     Action knowledge says applies to the attack type, target = the first collected indicator of the kind the
 *     action operates on (host actions -> the alerting agent). Actions with no such indicator are skipped and recorded.
 *  4. Decision: NOT measured (see below).
 *
 * The plan is scored with the SAME deterministic functions VIGIX uses (playbook alignment, attack alignment, evidence
 * support, and the Action's required evidence via `missingEvidenceForTarget` + the ACTION_COMPLIANCE policies).
 * Policy/approval criteria are not applicable: the baseline has no approval workflow.
 *
 * Timing: `investigation_time_seconds` is the wall-clock duration of THIS procedure (evidence collection through
 * plan creation) — a machine procedure latency, comparable in definition (investigation start -> a proposed
 * response is available) to VIGIX's Investigation Time but NOT in content (no LLM stage). `decision_*` are NULL:
 * no human or approval instance exists in the baseline, and a human reaction time must not be invented.
 *
 *   cd apps/backend && EVAL_DB=soar_addl_eval . scripts/eval/eval-env.sh
 *   npx ts-node --transpile-only scripts/eval/additional/baseline.ts
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { extractAlertIocs } from "../../../src/domain/investigation/alertIocs";
import { summarizeAlert } from "../../../src/domain/alert/alertSummary";
import { iocKind } from "../../../src/domain/knowledge/knowledgeTypes";
import { findActionKnowledge } from "../../../src/domain/knowledge/actionKnowledge";
import { attackTypeForIncidentType } from "../../../src/domain/knowledge/attackKnowledge";
import { PlaybookSelector } from "../../../src/application/recommendation/services/PlaybookSelector";
import { missingEvidenceForTarget } from "../../../src/application/recommendation/services/ActionEvidence";
import { PrismaPlaybookRepository } from "../../../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaPolicyRepository } from "../../../src/infrastructure/database/postgres/repositories/PolicyRepository.prisma";
import { PolicyEvaluator } from "../../../src/infrastructure/policy-engine/PolicyEvaluator";
import { TENANT, DATA, CLEAN_LABEL, INTERVENTION_LABEL, frozenRun, assertAdditionalDb, indexerAlertById, stats, r2 } from "./common";

(async () => {
  const db = assertAdditionalDb();
  const prisma = new PrismaClient();
  const playbookRepo = new PrismaPlaybookRepository(prisma);
  const policy = new PolicyEvaluator(new PrismaPolicyRepository(prisma));
  const selector = new PlaybookSelector();
  const clean = frozenRun(CLEAN_LABEL), interv = frozenRun(INTERVENTION_LABEL);
  const actionRows = await prisma.action.findMany({ select: { code: true, enabled: true, category: true } });
  const actionByCode = new Map(actionRows.map((a) => [a.code, a]));
  const startedAt = new Date().toISOString();
  const cases: any[] = [];

  for (const c of clean.cases) {
    if (c.environmentStatus === "ENVIRONMENT_UNAVAILABLE" || !c.incidentId) { cases.push({ case_id: c.caseId, completion_status: "NOT_EVALUATED — ENVIRONMENT_UNAVAILABLE (TC-05: no Windows endpoint); nothing fabricated" }); continue; }
    const gt = c.groundTruth;
    const alertRow = await prisma.alert.findUnique({ where: { id: c.alertId } });
    const docId = c.wazuh.indexerDocId as string;

    // ---------------- timed procedure ----------------
    const t0 = new Date();
    const raw = await indexerAlertById(docId);                                   // 1. evidence collection (same alert, Wazuh Indexer)
    if (!raw) { cases.push({ case_id: c.caseId, completion_status: "FAILED — alert not found in the Wazuh Indexer" }); continue; }
    const indicators = extractAlertIocs(raw);                                    //    same deterministic extractor as VIGIX
    const summary = summarizeAlert(raw);
    const agent = summary.host as string;
    const playbooks = await playbookRepo.findAll(TENANT);                        // 2. investigation: alert-declared MITRE -> playbook
    const selected = selector.select(playbooks, summary.mitreTechniques, summary.mitreTechniques);
    const planned: { action: string; target: string; targetKind: string }[] = [];
    const skipped: { action: string; reason: string }[] = [];
    if (selected) {
      const attackType = attackTypeForIncidentType(selected.incidentType);
      for (const code of selected.allowedActions) {                              // 3. static playbook lookup
        const row = actionByCode.get(code), knowledge = findActionKnowledge(code);
        if (!row || !row.enabled || row.category !== "CONTAINMENT" || !knowledge) { skipped.push({ action: code, reason: "not an enabled containment action with knowledge" }); continue; }
        if (attackType && !knowledge.applicableAttackTypes.includes(attackType)) { skipped.push({ action: code, reason: `not applicable to ${attackType}` }); continue; }
        const kind = knowledge.targetKind;
        const target = kind === "host" ? agent : indicators.find((i) => iocKind(i.iocType) === kind)?.value;
        if (!target) { skipped.push({ action: code, reason: `no collected indicator of kind '${kind}'` }); continue; }
        planned.push({ action: code, target, targetKind: String(kind) });
      }
    }
    const t1 = new Date();                                                       // response plan available
    // ---------------- end of timed procedure ----------------

    // deterministic scoring with the same functions VIGIX uses
    const ctx = {
      iocs: indicators.map((i) => ({ iocType: i.iocType, iocValue: i.value, source: "ALERT", reputationScore: null, manual: true })),
      evidence: [{ type: "ALERT", source: "wazuh", origin: "SYSTEM", title: String(summary.ruleDescription ?? ""), timestamp: String(raw.timestamp), host: agent, ruleId: summary.ruleId, iocValues: indicators.map((i) => i.value) }],
      affectedHosts: [agent],
    } as any;
    const stepChecks = [];
    for (const p of planned) {
      const required = (await policy.actionCompliance(TENANT, { actionCode: p.action })).requiredEvidence;
      const missing = missingEvidenceForTarget(ctx, p.action, p.target, required);
      stepChecks.push({ ...p, requiredEvidenceMissing: missing, requiredEvidenceSatisfied: missing.length === 0, targetInCollectedEvidence: p.targetKind === "host" ? p.target === agent : indicators.some((i) => i.value === p.target) });
    }
    const allowed: string[] = gt.allowedActions;
    const attackAlignment = planned.length > 0 && planned.every((p) => allowed.includes(p.action));
    const evidenceSupport = planned.length > 0 && stepChecks.every((s) => s.targetInCollectedEvidence);
    const requiredEvidenceOk = planned.length > 0 && stepChecks.every((s) => s.requiredEvidenceSatisfied);
    const playbookAlignment = selected?.code === gt.expectedPlaybook;
    const preferredHit = planned.some((p) => (gt.expectedActions as string[]).includes(p.action));
    const baselineValid = attackAlignment && evidenceSupport && requiredEvidenceOk && playbookAlignment;
    const stepsBlockedByRequiredEvidence = stepChecks.filter((s) => !s.requiredEvidenceSatisfied).length;

    // what VIGIX had for the same case (frozen Clean Run v2 / Intervention Run v2 — read only)
    const iv = interv.cases.find((x: any) => x.caseId === c.caseId);
    const [vigixIocs] = await prisma.$queryRawUnsafe<any[]>("select count(*)::int n from threat_intel_iocs where incident_id::text=$1", c.incidentId);
    const [vigixEv] = await prisma.$queryRawUnsafe<any[]>("select count(*)::int n from evidence e join investigations i on i.id=e.investigation_id where i.incident_id::text=$1", c.incidentId);
    cases.push({
      case_id: c.caseId, attack: c.attackName,
      alert_timestamp: alertRow?.receivedAt.toISOString() ?? null, wazuh_alert_doc: docId,
      investigation_start: t0.toISOString(), investigation_end: t1.toISOString(), investigation_time_seconds: r2((t1.getTime() - t0.getTime()) / 1000),
      response_plan_created_at: t1.toISOString(),
      decision_timestamp: null, decision_latency_seconds: null,
      decision_null_reason: "The baseline has no approval workflow instance and no human participant; a decision time would have to be invented. NULL on purpose.",
      evidence_count: indicators.length + 1, indicator_count: indicators.length, evidence_definition: "alert record (1) + indicators extracted by the deterministic extractor",
      response_action_count: planned.length,
      completion_status: !selected ? "NO_PLAN — no playbook matched the alert's MITRE techniques" : planned.length === 0 ? "NO_PLAN — playbook selected but no action had a target in the collected evidence" : "PLAN_CREATED",
      selected_playbook: selected?.code ?? null, expected_playbook: gt.expectedPlaybook, playbook_alignment: playbookAlignment,
      plan: planned, skipped_actions: skipped, step_checks: stepChecks,
      attack_alignment: attackAlignment, evidence_support: evidenceSupport, required_evidence_satisfied: requiredEvidenceOk, steps_blocked_by_required_evidence: stepsBlockedByRequiredEvidence,
      preferred_action_hit: preferredHit, baseline_plan_valid_4_criteria: baselineValid,
      vigix_clean: { compliance: c.recommendationCompliance, investigation_seconds: c.investigationTimeSeconds, actions: c.actionMatch?.actualActions ?? [], targets: c.actionMatch?.actualTargets ?? [], playbook: c.playbookCode, indicator_count_in_incident: vigixIocs.n, evidence_rows: vigixEv.n, retries: c.invalidOutputCount, checks: c.compliance ? { attackAlignment: c.compliance.attackAlignment, evidenceSupport: c.compliance.evidenceSupport, knowledgeValidity: c.compliance.knowledgeValidity, playbookAlignment: c.compliance.playbookAlignment } : null },
      vigix_intervention: iv ? { compliance: iv.recommendationCompliance, investigation_seconds: iv.investigationTimeSeconds, actions: iv.actionMatch?.actualActions ?? [] } : null,
    });
    console.log(`${c.caseId}: ${cases[cases.length - 1].completion_status} playbook=${selected?.code} actions=${planned.length} valid=${baselineValid} t=${cases[cases.length - 1].investigation_time_seconds}s (VIGIX: ${c.recommendationCompliance}, ${c.investigationTimeSeconds}s)`);
  }

  const done = cases.filter((x) => x.investigation_time_seconds !== undefined);
  const withPlan = done.filter((x) => x.completion_status === "PLAN_CREATED");
  const vg = done.filter((x) => x.vigix_clean.compliance !== "NOT_EVALUATED");
  const summary = {
    population: `${done.length} evaluable cases (TC-05 unavailable, not fabricated)`,
    plan_created: { numerator: withPlan.length, denominator: done.length },
    baseline_valid_4_criteria: { numerator: done.filter((x) => x.baseline_plan_valid_4_criteria).length, denominator: done.length },
    playbook_alignment: { numerator: done.filter((x) => x.playbook_alignment).length, denominator: done.length },
    attack_alignment: { numerator: done.filter((x) => x.attack_alignment).length, denominator: done.length },
    evidence_support: { numerator: done.filter((x) => x.evidence_support).length, denominator: done.length },
    required_evidence_satisfied: { numerator: done.filter((x) => x.required_evidence_satisfied).length, denominator: done.length },
    preferred_action_hit: { numerator: done.filter((x) => x.preferred_action_hit).length, denominator: done.length },
    plan_steps_total: withPlan.reduce((a, x) => a + x.response_action_count, 0),
    plan_steps_blocked_by_required_evidence: done.reduce((a, x) => a + x.steps_blocked_by_required_evidence, 0),
    investigation_time_seconds: stats(done.map((x) => x.investigation_time_seconds)),
    evidence_count: stats(done.map((x) => x.evidence_count)),
    response_action_count: stats(done.map((x) => x.response_action_count)),
    vigix_clean_same_cases: {
      recommendations_evaluated: { numerator: vg.length, denominator: done.length },
      playbook_alignment_among_evaluated: { numerator: vg.filter((x) => x.vigix_clean.checks?.playbookAlignment).length, denominator: vg.length },
      attack_alignment_among_evaluated: { numerator: vg.filter((x) => x.vigix_clean.checks?.attackAlignment).length, denominator: vg.length },
      evidence_support_among_evaluated: { numerator: vg.filter((x) => x.vigix_clean.checks?.evidenceSupport).length, denominator: vg.length },
      investigation_time_seconds: stats(done.map((x) => x.vigix_clean.investigation_seconds)),
      indicator_count_in_incident: stats(done.map((x) => x.vigix_clean.indicator_count_in_incident)),
      response_action_count: stats(done.map((x) => x.vigix_clean.actions.length)),
    },
  };
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(path.join(DATA, "baseline.json"), JSON.stringify({ evaluation: "A_controlled_procedural_baseline", label: "Controlled procedural baseline (static playbook lookup, no AI, no human)", startedAt, finishedAt: new Date().toISOString(), database: db, source_alerts: `frozen ${CLEAN_LABEL} (same alerts, read from the Wazuh Indexer)`, humanStudy: false, mockUsed: false, cases, summary }, null, 2));
  console.log("\nSUMMARY", JSON.stringify(summary, null, 1).slice(0, 2500));
  await prisma.$disconnect();
})().catch((e) => { console.error("baseline crashed:", String(e?.stack ?? e).slice(0, 1200)); process.exit(2); });
