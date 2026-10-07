/**
 * build-paper-outputs.ts — renders the paper datasets and documents of the additional evaluation from MEASURED files:
 *   results/evaluation-audit.json (FROZEN main evaluation), results/additional-evaluation/data/{baseline,consistency,negative}.json
 * Writes (all under results/additional-evaluation/): paper-metrics.json, figure-data.json, paper-results.md,
 * figure-captions.md, paper-results-narrative.md. No database, no network, no evaluation is run here.
 * It first CHECKS that the frozen values quoted in the task still equal the audit file, and stops if not.
 *
 *   cd apps/backend && npx ts-node --transpile-only scripts/eval/additional/build-paper-outputs.ts
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { ADD, DATA, RES, CLEAN_LABEL, INTERVENTION_LABEL, frozenRun, stats, r2 } from "./common";

const J = (p: string) => JSON.parse(fs.readFileSync(p, "utf8"));
const A = J(path.join(RES, "evaluation-audit.json"));
const B = J(path.join(DATA, "baseline.json"));
const C = J(path.join(DATA, "consistency.json"));
const N = J(path.join(DATA, "negative.json"));
const cleanRun = frozenRun(CLEAN_LABEL), ivRun = frozenRun(INTERVENTION_LABEL);
const CL = A.kpi["real-clean"], IV = A.kpi["real-intervention"];
const CTRL_LABEL = "control-recurrence-real-wazuh-20260930";
const pct = (n: number, d: number) => (d ? r2((n / d) * 100) : null);
const AUDIT = "results/evaluation-audit.json";

// ------------------------------------------------------------------ frozen-value check (fail loudly, never overwrite)
const frozen: [string, unknown, unknown][] = [
  ["clean compliance evaluated", `${CL.recommendationCompliance.numerator}/${CL.recommendationCompliance.denominator}`, "7/7"],
  ["clean compliance attempted %", CL.recommendationCompliance.pctOfAttempted, 77.78],
  ["clean workflow", `${CL.workflowCompletion.numerator}/${CL.workflowCompletion.denominator} ${CL.workflowCompletion.pct}`, "5/9 55.56"],
  ["clean intervention %", CL.interventionRate.pct, 0],
  ["clean retry cases", `${CL.retry.caseRateNumerator}/${CL.retry.caseRateDenominator} ${CL.retry.caseRatePct}`, "2/9 22.22"],
  ["clean investigation mean/n", `${CL.investigationTime.mean} ${CL.investigationTime.n}`, "40.27 7"],
  ["clean D→R (ingest) mean/n", `${CL.detectionToResponse.fromVigixIngest.mean} ${CL.detectionToResponse.fromVigixIngest.n}`, "40.39 7"],
  ["clean verification time mean/n", `${CL.verificationTime.total.mean} ${CL.verificationTime.total.n}`, "0.03 5"],
  ["clean verification outcomes", JSON.stringify(CL.verificationEffectiveness.outcomes), JSON.stringify({ RESOLVED: 5, ERROR: 2 })],
  ["intervention compliance", `${IV.recommendationCompliance.numerator}/${IV.recommendationCompliance.denominator}`, "9/9"],
  ["intervention workflow", `${IV.workflowCompletion.numerator}/${IV.workflowCompletion.denominator} ${IV.workflowCompletion.pct}`, "7/9 77.78"],
  ["intervention intervention rate", `${IV.interventionRate.numerator}/${IV.interventionRate.denominator} ${IV.interventionRate.pct}`, "2/9 22.22"],
  ["intervention retry cases", `${IV.retry.caseRateNumerator}/${IV.retry.caseRateDenominator} ${IV.retry.caseRatePct}`, "2/9 22.22"],
  ["intervention investigation mean/n", `${IV.investigationTime.mean} ${IV.investigationTime.n}`, "72.23 9"],
  ["intervention D→R (ingest) mean/n", `${IV.detectionToResponse.fromVigixIngest.mean} ${IV.detectionToResponse.fromVigixIngest.n}`, "72.34 9"],
  ["intervention verification time mean/n", `${IV.verificationTime.total.mean} ${IV.verificationTime.total.n}`, "0.03 7"],
  ["intervention verification outcomes", JSON.stringify(IV.verificationEffectiveness.outcomes), JSON.stringify({ RESOLVED: 7, ERROR: 2 })],
];
const bad = frozen.filter(([, got, want]) => String(got) !== String(want));
if (bad.length) { console.error("FROZEN VALUE MISMATCH — stopping (nothing written):", JSON.stringify(bad)); process.exit(3); }
console.log(`frozen-value check: ${frozen.length}/${frozen.length} values identical to ${AUDIT}`);

// ------------------------------------------------------------------ derived numbers
const rows = (key: string): any[] => A.cases[key].filter((r: any) => r.environmentStatus !== "ENVIRONMENT_UNAVAILABLE");
const critCount = (key: string, k: string) => rows(key).filter((r: any) => r.rescored?.checks?.[k]).length;
const vigixActions = (key: string) => rows(key).filter((r: any) => r.recommendation1).map((r: any) => r.recommendation1.steps.length);
const baselineMs = B.cases.filter((c: any) => c.investigation_start).map((c: any) => (Date.parse(c.investigation_end) - Date.parse(c.investigation_start)) / 1000);
const bt = (() => { const v = [...baselineMs].sort((a, b) => a - b); const mean = v.reduce((a, b) => a + b, 0) / v.length; const med = v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2; const sd = Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (v.length - 1)); const f3 = (x: number) => Math.round(x * 1000) / 1000; return { n: v.length, mean: f3(mean), median: f3(med), min: f3(v[0]), max: f3(v[v.length - 1]), sd: f3(sd), sum: f3(v.reduce((a, b) => a + b, 0)), values: v.map(f3) }; })();
const clSecs = rows("real-clean").map((r: any) => r.times?.investigationSeconds).filter((x: any) => typeof x === "number");
const ivSecs = rows("real-intervention").map((r: any) => r.times?.investigationSeconds).filter((x: any) => typeof x === "number");
const sum = (xs: number[]) => r2(xs.reduce((a, b) => a + b, 0));
const bs = B.summary;
const ov = C.overall;
const ENDPOINT_IP = String(cleanRun.cases.find((c: any) => c.simulation)?.simulation?.facts?.endpointIp ?? "");
let ipSteps = 0; const selfSteps: string[] = [];
for (const r of C.runs) for (const st of r.all_steps ?? []) if (["ACT-BLOCK-SOURCE-IP", "ACT-BLOCK-DESTINATION-IP"].includes(st.action)) { ipSteps++; if (st.target === ENDPOINT_IP) selfSteps.push(`${r.case_id}#${r.repetition} ${st.action}`); }
const negS = N.summary;
const gates = N.governance_gates as any[];
// The layer that ACTUALLY rejected each scenario (from the recorded policy_result) vs the layer the scenario was expected to test.
const scn = N.scenarios as any[];
const actualLayer = (x: any) => (String(x.policy_result).startsWith("POLICY-DERIVED") ? "POLICY" : "VALIDATOR");
const byActual = { policy: { rejected: scn.filter((x) => actualLayer(x) === "POLICY" && x.actual_result === "REJECTED").length, total: scn.filter((x) => actualLayer(x) === "POLICY").length }, validator: { rejected: scn.filter((x) => actualLayer(x) === "VALIDATOR" && x.actual_result === "REJECTED").length, total: scn.filter((x) => actualLayer(x) === "VALIDATOR").length } };
const layerMismatch = scn.filter((x) => x.expected_layer !== actualLayer(x)).map((x) => x.case_id);
const layerText = `Policy-derived rules rejected ${byActual.policy.rejected} scenarios (${scn.filter((x) => actualLayer(x) === "POLICY").map((x) => x.case_id).join(", ")}: responsible role, approval waiver) and validator knowledge/grounding rules rejected ${byActual.validator.rejected}${layerMismatch.length ? `; ${layerMismatch.join(", ")} was expected at the Policy layer but the required evidence (COMMAND_LINE for ACT-KILL-PROCESS) comes from the Action's own knowledge, not from an ACTION_COMPLIANCE policy, so it was rejected at the validator layer — the layer expectation was mis-specified, the rejection itself occurred` : ""}`;
const ctrl = A.control;
const baseRun = (f: string, j: any) => `${f}-${String(j.startedAt).replace(/[-:.]/g, "").slice(0, 15)}`;
const RUN = { baseline: baseRun("additional-baseline", B), consistency: baseRun("additional-consistency", C), negative: baseRun("additional-negative", N) };

// ------------------------------------------------------------------ paper-metrics.json
type Metric = { value: unknown; numerator: unknown; denominator: unknown; population: string; source: string; run_id: string; interpretation: string; limitation: string; [k: string]: unknown };
const M = (value: unknown, numerator: unknown, denominator: unknown, population: string, source: string, run_id: string, interpretation: string, limitation: string, extra: Record<string, unknown> = {}): Metric => ({ value, numerator, denominator, population, source, run_id, interpretation, limitation, ...extra });
const timeMetric = (s: any, secs: number[], population: string, source: string, run_id: string, interp: string, lim: string) => M(s.mean, sum(secs), s.n, population, source, run_id, interp, lim, { unit: "seconds", statistic: "mean", median: s.median, sd: s.sd, min: s.min, max: s.max, n: s.n, numerator_meaning: "sum of the measured durations (s)" });
const LIM_SAMPLE = "10 predefined test cases (9 evaluable; TC-05 needs a Windows endpoint that does not exist); one run per condition; not representative of all SOC situations.";
const CLR = CLEAN_LABEL, IVR = INTERVENTION_LABEL;

const metrics: Record<string, Record<string, Metric>> = {
  recommendation_compliance: {
    clean_run__among_evaluated: M(CL.recommendationCompliance.pct, 7, 7, "recommendations that passed the validator and were scored (Clean Run v2)", `${AUDIT}#kpi.real-clean.recommendationCompliance`, CLR, "Share of validated recommendations satisfying all six deterministic criteria (attack alignment, evidence support, knowledge validity, policy compliance, playbook alignment, approval correctness). Not accuracy.", `${LIM_SAMPLE} Cases that produced no valid recommendation (TC-03, TC-08) are outside this denominator.`),
    clean_run__among_attempted: M(CL.recommendationCompliance.pctOfAttempted, 7, 9, "all attempted cases (Clean Run v2)", `${AUDIT}#kpi.real-clean.recommendationCompliance`, CLR, "Same numerator over every attempted case; a case with no valid recommendation counts as not compliant.", LIM_SAMPLE),
    intervention_run__among_evaluated: M(IV.recommendationCompliance.pct, 9, 9, "recommendations scored after analyst IOC correction (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.recommendationCompliance`, IVR, "Compliance of an analyst-assisted condition; must be reported next to the Clean Run and never as unaided performance.", `${LIM_SAMPLE} The analyst is a fixed script.`),
  },
  evidence_coverage: {
    clean_run__per_attempted_case: M(CL.evidenceCoverage.pctOfAttempted, CL.evidenceCoverage.casesWithRecommendationAllTargetsEvidenceBacked, CL.evidenceCoverage.denominatorAttempted, "attempted cases (Clean Run v2)", `${AUDIT}#kpi.real-clean.evidenceCoverage`, CLR, "Cases whose recommendation has every step target evidence-backed (evidence-linked IOC, analyst-added IOC or affected host); cases without a validator-passing recommendation count as not covered.", "Membership test, not semantic: a step aimed at the endpoint's own IP (TC-07) is counted as covered. Per-recommendation coverage is 100% by construction of the validator and is not reported as a result."),
    intervention_run__per_attempted_case: M(IV.evidenceCoverage.pctOfAttempted, IV.evidenceCoverage.casesWithRecommendationAllTargetsEvidenceBacked, IV.evidenceCoverage.denominatorAttempted, "attempted cases (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.evidenceCoverage`, IVR, "As above, after analyst IOC correction.", "As above; obtained with analyst intervention."),
  },
  playbook_alignment: {
    clean_run: M(CL.playbookAlignment.pct, CL.playbookAlignment.numerator, CL.playbookAlignment.denominator, "validated recommendations (Clean Run v2)", `${AUDIT}#kpi.real-clean.playbookAlignment`, CLR, "Selected playbook equals the ground-truth playbook and every action is inside it.", "Measured after a PlaybookSelector tie-break defect (TC-09 chose PB-C2) was fixed; that defect and fix are disclosed in the main evaluation findings."),
    intervention_run: M(IV.playbookAlignment.pct, IV.playbookAlignment.numerator, IV.playbookAlignment.denominator, "validated recommendations (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.playbookAlignment`, IVR, "As above.", "As above."),
  },
  policy_compliance: {
    clean_run: M(CL.policyCompliance.pct, CL.policyCompliance.numerator, CL.policyCompliance.denominator, "validated recommendations (Clean Run v2)", `${AUDIT}#kpi.real-clean.policyCompliance`, CLR, "Step approval flag equals the Policy snapshot and a responsible role is present.", "Current Policy implementation is the source of truth; negative policy behaviour is covered separately in the negative validation."),
    intervention_run: M(IV.policyCompliance.pct, IV.policyCompliance.numerator, IV.policyCompliance.denominator, "validated recommendations (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.policyCompliance`, IVR, "As above.", "As above."),
  },
  workflow_completion: {
    clean_run: M(CL.workflowCompletion.pct, CL.workflowCompletion.numerator, CL.workflowCompletion.denominator, "attempted cases (Clean Run v2)", `${AUDIT}#kpi.real-clean.workflowCompletion`, CLR, "All 11 workflow steps present in the database through a stored verification; does not mean RESOLVED.", "Incomplete cases: 2 without a valid recommendation, 2 whose re-hunt had no searchable IOC."),
    intervention_run: M(IV.workflowCompletion.pct, IV.workflowCompletion.numerator, IV.workflowCompletion.denominator, "attempted cases (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.workflowCompletion`, IVR, "As above.", "Incomplete cases: 2 whose re-hunt had no searchable IOC."),
  },
  investigation_time: {
    clean_run: timeMetric(CL.investigationTime, clSecs, "cases with a recommendation (Clean Run v2)", `${AUDIT}#kpi.real-clean.investigationTime`, CLR, "T_recommendation − T_investigation_start, uninterrupted scripted run; includes third-party LLM latency.", "Excludes the two cases with no valid recommendation (right-censored); no human in the loop."),
    intervention_run: timeMetric(IV.investigationTime, ivSecs, "cases with a recommendation (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.investigationTime`, IVR, "As above, including retry rounds and the analyst-correction step.", "As above."),
  },
  detection_to_response: {
    clean_run__from_vigix_ingest: M(CL.detectionToResponse.fromVigixIngest.mean, null, CL.detectionToResponse.fromVigixIngest.n, "executed responses (Clean Run v2)", `${AUDIT}#kpi.real-clean.detectionToResponse.fromVigixIngest`, CLR, "T_response_start − T_alert_received_by_VIGIX; includes LLM latency and a scripted SOC/IR step.", "Webhook (custom-vigix → backend) latency was not part of the evaluation path.", { unit: "seconds", statistic: "mean", median: CL.detectionToResponse.fromVigixIngest.median, sd: CL.detectionToResponse.fromVigixIngest.sd, min: CL.detectionToResponse.fromVigixIngest.min, max: CL.detectionToResponse.fromVigixIngest.max, n: CL.detectionToResponse.fromVigixIngest.n }),
    intervention_run__from_vigix_ingest: M(IV.detectionToResponse.fromVigixIngest.mean, null, IV.detectionToResponse.fromVigixIngest.n, "executed responses (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.detectionToResponse.fromVigixIngest`, IVR, "As above.", "As above.", { unit: "seconds", statistic: "mean", median: IV.detectionToResponse.fromVigixIngest.median, sd: IV.detectionToResponse.fromVigixIngest.sd, min: IV.detectionToResponse.fromVigixIngest.min, max: IV.detectionToResponse.fromVigixIngest.max, n: IV.detectionToResponse.fromVigixIngest.n }),
  },
  verification_time: {
    clean_run: M(CL.verificationTime.total.mean, null, CL.verificationTime.total.n, "stored verifications (Clean Run v2)", `${AUDIT}#kpi.real-clean.verificationTime.total`, CLR, "REHUNT_STARTED → verification stored (Wazuh Indexer query plus verification); total only.", "Query and processing time cannot be separated; small index; excludes the harness' indexer-refresh wait.", { unit: "seconds", statistic: "mean", median: CL.verificationTime.total.median, sd: CL.verificationTime.total.sd, min: CL.verificationTime.total.min, max: CL.verificationTime.total.max, n: CL.verificationTime.total.n }),
    intervention_run: M(IV.verificationTime.total.mean, null, IV.verificationTime.total.n, "stored verifications (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.verificationTime.total`, IVR, "As above.", "As above.", { unit: "seconds", statistic: "mean", median: IV.verificationTime.total.median, sd: IV.verificationTime.total.sd, min: IV.verificationTime.total.min, max: IV.verificationTime.total.max, n: IV.verificationTime.total.n }),
  },
  intervention_rate: {
    clean_run: M(CL.interventionRate.pct, CL.interventionRate.numerator, CL.interventionRate.denominator, "attempted cases (Clean Run v2)", `${AUDIT}#kpi.real-clean.interventionRate`, CLR, "0% by construction: no correction is allowed in a Clean Run; blocked cases are counted as failures instead.", LIM_SAMPLE),
    intervention_run: M(IV.interventionRate.pct, IV.interventionRate.numerator, IV.interventionRate.denominator, "attempted cases (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.interventionRate`, IVR, "Cases in which an analyst IOC correction was needed (TC-03 e-mail, TC-08 process/command).", "The analyst is a fixed script, not a human judgement."),
  },
  retry_rate: {
    clean_run: M(CL.retry.caseRatePct, CL.retry.caseRateNumerator, CL.retry.caseRateDenominator, "attempted cases (Clean Run v2)", `${AUDIT}#kpi.real-clean.retry`, CLR, "Cases with at least one failed generation call. Total retry count is a count, not a percentage.", "Retry counts of the two blocked cases are censored at the harness cap of 5.", { total_retry_count: CL.retry.totalRetryCount, average_retries_per_case: CL.retry.averagePerCase, per_case: CL.retry.perCase }),
    intervention_run: M(IV.retry.caseRatePct, IV.retry.caseRateNumerator, IV.retry.caseRateDenominator, "attempted cases (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.retry`, IVR, "As above.", "As above.", { total_retry_count: IV.retry.totalRetryCount, average_retries_per_case: IV.retry.averagePerCase, per_case: IV.retry.perCase }),
  },
  verification_outcomes: {
    clean_run: M(CL.verificationEffectiveness.outcomes, CL.verificationEffectiveness.numerator, CL.verificationEffectiveness.denominator, "cases with a completed (simulated) response (Clean Run v2)", `${AUDIT}#kpi.real-clean.verificationEffectiveness`, CLR, "Outcome distribution of the real re-hunt. RESOLVED = the verification procedure did not detect the specified recurrence condition within the tested verification window. ERROR = the re-hunt could not run (no searchable IOC).", "Not proof of eradication or containment: responses were simulated, each attack ran once, and only IP/domain/URL/hash IOCs are searchable."),
    intervention_run: M(IV.verificationEffectiveness.outcomes, IV.verificationEffectiveness.numerator, IV.verificationEffectiveness.denominator, "cases with a completed (simulated) response (Intervention Run v2)", `${AUDIT}#kpi.real-intervention.verificationEffectiveness`, IVR, "As above.", "As above."),
  },
  recurrence_detection: {
    control_tc01: M({ result: ctrl.result, matching_events: ctrl.matchingEvents, ioc_recurrence: ctrl.iocRecurrence, threat_contained: ctrl.threatContained, spread_detected: ctrl.spreadDetected, incident_status: ctrl.incidentStatus, investigations: ctrl.investigations }, 1, 1, "single control: the TC-01 attack repeated after the simulated response", `${AUDIT}#control`, CTRL_LABEL, "The real re-hunt detected the recurring attacker IP (29 matching events) and returned NOT_RESOLVED; the incident stayed open and Investigation #2 was opened by Policy.", "One positive control on one case and one IOC type; no negative control, no spread-detection test."),
  },
  baseline_investigation_time: {
    controlled_procedural_baseline: M(bt.mean, bt.sum, bt.n, "9 evaluable cases, same alerts as the Clean Run", "results/additional-evaluation/data/baseline.json", RUN.baseline, "Wall-clock duration of a deterministic, non-AI procedure (evidence collection from the Wazuh Indexer → alert-declared MITRE → playbook lookup → response plan). Same interval definition as VIGIX Investigation Time (investigation start → a proposed response is available), but different content: no LLM stage.", "Machine procedure latency, NOT human analyst performance; must not be read as a real-world baseline or a speed-up claim.", { unit: "seconds", statistic: "mean", median: bt.median, sd: bt.sd, min: bt.min, max: bt.max, n: bt.n, numerator_meaning: "sum of the measured durations (s)" }),
  },
  baseline_decision_latency: {
    controlled_procedural_baseline: M(null, null, 0, "9 evaluable cases", "results/additional-evaluation/data/baseline.json", RUN.baseline, "NOT MEASURED (NULL). The baseline has no approval workflow instance and no human participant; a decision latency would have to be invented.", "No baseline decision latency exists; VIGIX Time-to-Decision (a scripted approval, ≈0.06 s) is therefore not compared with anything.", { n: 0, null_reason: "no human or approval instance in the baseline; reaction time is not invented" }),
  },
  recommendation_consistency: {
    overall_pooled: M(ov.consistency_pct, ov.consistent_runs, ov.runs, `${C.cases.length} cases × ${C.repetitions} repetitions on identical evidence snapshots (Clean Run v2 incidents)`, "results/additional-evaluation/data/consistency.json", RUN.consistency, "Runs whose validated primary recommendation (same playbook, primary action, target type and target value) equals the modal one, over all runs. Not accuracy.", "Single LLM (vllm-spark-01/gemma4-26b-uncensored on a self-hosted vLLM server); representative cases only; 10 calls that failed because the LLM endpoint was unreachable (timeout / ConnectError) are excluded and listed; identical evidence is held fixed, so this measures the AI stage alone; first-round context (earlier recommendations hidden) as in the original generation.", { per_case_mean_pct: ov.per_case_mean_pct, per_case_sd_pct: ov.per_case_sd_pct, validated_runs: ov.validated_runs, all_evidence_snapshots_identical: ov.all_evidence_snapshots_identical, per_case: Object.fromEntries(C.perCase.map((c: any) => [c.case_id, { consistent_runs: c.consistent_runs, runs: c.runs, consistency_pct: c.consistency_pct, validated_runs: c.validated_runs, distinct_primary_recommendations: c.distinct_primary_recommendations, step_set_agreement_pct: c.step_set_agreement_pct }])) }),
  },
  unsupported_recommendation_rejection_rate: {
    controlled_invalid_recommendations: M(negS.unsupported_recommendation_rejection_rate.pct, negS.unsupported_recommendation_rejection_rate.numerator, negS.unsupported_recommendation_rejection_rate.denominator, `${negS.scenarios_total} controlled invalid recommendations (each a validated candidate with ONE injected fault)`, "results/additional-evaluation/data/negative.json", RUN.negative, "Share of controlled invalid recommendations rejected by the deterministic validator/Policy checks; every scenario had a positive control proving the unmodified candidate validates.", "Scenarios are single-fault and written by the evaluator; they test rule coverage, not the AI, and are not adversarial or multi-fault.", { rejected_with_expected_code: negS.rejected_with_expected_code, by_expected_layer: negS.by_layer, by_actual_layer: byActual, layer_expectation_mismatch: layerMismatch, accepted_invalid: negS.accepted_invalid }),
  },
  self_targeting_steps_in_repeated_runs: {
    consistency_runs: M(pct(selfSteps.length, ipSteps), selfSteps.length, ipSteps, `${ipSteps} IP-blocking steps in ${C.runs.length} repeated recommendation runs`, "results/additional-evaluation/data/consistency.json", RUN.consistency, `IP-blocking steps aimed at the monitored endpoint's own address (${ENDPOINT_IP}): ${selfSteps.join("; ") || "none"}. In the frozen runs such a step was the primary step of TC-07 (both runs) and occurred in TC-09 (Intervention Run).`, "Supplementary deterministic observation outside the six compliance criteria; the evidence-support criterion cannot see the role of an IP.", { self_targeting: selfSteps }),
  },
  governance_gate_checks: {
    human_and_policy_gates: M(pct(negS.governance_gates.passed, negS.governance_gates.total), negS.governance_gates.passed, negS.governance_gates.total, "17 checks with the real use cases on the cloned database", "results/additional-evaluation/data/negative.json#governance_gates", RUN.negative, "IR reject → PENDING_MANUAL_DECISION without execution and without closing the incident; manual decision only by IR with a note; wrong-role, AI and admin approvals denied; start before approval, re-hunt before completion and manual RESOLVED are blocked.", "One incident and one reject path exercised; expected outcomes were defined before the checks ran."),
  },
};
fs.writeFileSync(path.join(ADD, "paper-metrics.json"), JSON.stringify({ generatedAt: new Date().toISOString(), frozenSource: AUDIT, frozenValueCheck: `${frozen.length}/${frozen.length} quoted values identical to the audit`, corrections: [{ id: "C1-LLM-identity", affects_frozen_files_without_modifying_them: ["results/findings-and-limitations.md", "results/evaluation-summary.md", "results/evaluation-audit.md", "results/runs/*/run.json (preflight.env.llm)"], earlier_statement: "LLM: provider openrouter, model google/gemma-4-26b-a4b-it (assumed; LLM_PROVIDER is defined twice in apps/ai-orchestrator/.env)", verified_fact: "The orchestrator's analysis and recommendation calls use LlamaProvider(settings.llm_base_url, settings.llm_model, …) only; the model recorded in all 19 llm_analyst results of the frozen database is 'vllm-spark-01/gemma4-26b-uncensored' on a self-hosted OpenAI-compatible vLLM endpoint; 'google/gemma' appears in none of them. OPENROUTER_* settings are not used on that path.", effect_on_numbers: "none — no metric was computed from the provider name; only the description of the environment changes", how_verified: "source read (apps/ai-orchestrator/src/api/routes/recommendations.py, agents/llm_analyst_agent/agent.py, config/settings.py) and a query of agent_results.output in soar_eval" }], terminology: "Recommendation Compliance / Consistency, Evidence Coverage, Playbook Alignment, Policy Compliance, Workflow Completion, Verification Outcome, Recurrence Detection — never 'accuracy'; RESOLVED = the verification procedure did not detect the specified recurrence condition within the tested window (not proof of eradication).", conditions: { real_wazuh: "Clean Run v2 and Intervention Run v2 (frozen)", baseline: "controlled procedural baseline (new)", consistency: "repeated recommendation generation on identical evidence (new)", negative: "controlled invalid recommendations and governance gates (new)", previous_mock: "NOT used anywhere in this file (kept separately in results/evaluation.json)" }, metrics }, null, 2));

// ------------------------------------------------------------------ figure-data.json
const observed = ["RESOLVED", "ERROR", "NOT_RESOLVED"];
const fig = {
  fig1_main_metrics: { n_attempted: 9, n_evaluated: 7, metrics: [
    { label: "Recommendation\nCompliance", attempted_pct: CL.recommendationCompliance.pctOfAttempted, evaluated_pct: CL.recommendationCompliance.pct },
    { label: "Evidence\nCoverage", attempted_pct: CL.evidenceCoverage.pctOfAttempted, evaluated_pct: null },
    { label: "Playbook\nAlignment", attempted_pct: pct(CL.playbookAlignment.numerator, 9), evaluated_pct: CL.playbookAlignment.pct },
    { label: "Policy\nCompliance", attempted_pct: pct(CL.policyCompliance.numerator, 9), evaluated_pct: CL.policyCompliance.pct },
    { label: "Workflow\nCompletion", attempted_pct: CL.workflowCompletion.pct, evaluated_pct: null },
  ] },
  fig2_clean_vs_intervention: { n_clean: 9, n_intervention: 9, metrics: [
    { label: "Recommendation\nCompliance", clean_pct: CL.recommendationCompliance.pctOfAttempted, intervention_pct: IV.recommendationCompliance.pctOfAttempted },
    { label: "Workflow\nCompletion", clean_pct: CL.workflowCompletion.pct, intervention_pct: IV.workflowCompletion.pct },
  ] },
  fig3_investigation_time: { conditions: [
    { label: `Controlled procedural\nbaseline (no AI)`, mean: bt.mean, median: bt.median, sd: bt.sd, min: bt.min, max: bt.max, n: bt.n, values: bt.values },
    { label: "VIGIX\nClean Run", mean: CL.investigationTime.mean, median: CL.investigationTime.median, sd: CL.investigationTime.sd, min: CL.investigationTime.min, max: CL.investigationTime.max, n: CL.investigationTime.n, values: clSecs },
    { label: "VIGIX\nIntervention Run", mean: IV.investigationTime.mean, median: IV.investigationTime.median, sd: IV.investigationTime.sd, min: IV.investigationTime.min, max: IV.investigationTime.max, n: IV.investigationTime.n, values: ivSecs },
  ] },
  fig4_consistency: { repetitions: C.repetitions, overall_pct: ov.consistency_pct, overall_consistent: ov.consistent_runs, overall_runs: ov.runs, cases: C.perCase.map((c: any) => ({ case: c.case_id, consistency_pct: c.consistency_pct, consistent: c.consistent_runs, runs: c.runs })) },
  fig5_verification_outcomes: { categories_observed: observed, groups: [
    { label: `Clean Run\n(n=${CL.verificationEffectiveness.denominator})`, counts: { RESOLVED: CL.verificationEffectiveness.outcomes.RESOLVED ?? 0, ERROR: CL.verificationEffectiveness.outcomes.ERROR ?? 0 } },
    { label: `Intervention Run\n(n=${IV.verificationEffectiveness.denominator})`, counts: { RESOLVED: IV.verificationEffectiveness.outcomes.RESOLVED ?? 0, ERROR: IV.verificationEffectiveness.outcomes.ERROR ?? 0 } },
    { label: "Recurrence control\n(n=1)", counts: { NOT_RESOLVED: 1 } },
  ], not_observed: ["NOT_CONTAINED (only as a flag on the control's NOT_RESOLVED result)", "SPREAD"] },
  fig6_negative_validation: { total: negS.unsupported_recommendation_rejection_rate.denominator, rejected: negS.unsupported_recommendation_rejection_rate.numerator, accepted: negS.unsupported_recommendation_rejection_rate.denominator - negS.unsupported_recommendation_rejection_rate.numerator },
};
fs.writeFileSync(path.join(ADD, "figure-data.json"), JSON.stringify(fig, null, 2));

// ------------------------------------------------------------------ paper-results.md (Tables 1-6)
const T: string[] = [];
const P = (...s: string[]) => { if (!s.length) T.push(""); else T.push(...s); };
const row = (...c: unknown[]) => `| ${c.join(" | ")} |`;
const short = (s: string, n = 40) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
P("# VIGIX additional evaluation — paper results", "", `Generated ${new Date().toISOString()}. Real Wazuh main results are **frozen** (quoted from \`${AUDIT}\`; ${frozen.length} values checked identical). Baseline, consistency and negative validation are separate, newly measured conditions. The earlier MOCK evaluation is not used in any table. *Recommendation Compliance/Consistency* are not accuracy; *RESOLVED* means the verification procedure did not detect the specified recurrence condition within the tested window, not proof of eradication.`, "");

P("## Table 1 — Evaluation cases (Real Wazuh, Clean Run v2)", "");
P(row("Case", "Attack type", "Wazuh rule", "MITRE technique", "Evaluation status", "Recommendation (Clean Run)", "Verification"), row(...Array(7).fill("---")));
for (const r of A.cases["real-clean"]) {
  const gt = cleanRun.cases.find((c: any) => c.caseId === r.caseId)?.groundTruth;
  if (r.environmentStatus === "ENVIRONMENT_UNAVAILABLE") { P(row(r.caseId, r.attack, "–", "T1059.001 (expected)", "ENVIRONMENT_UNAVAILABLE (no Windows endpoint)", "not run", "not run")); continue; }
  const stock = gt?.mode === "STOCK_RULE" ? "stock rule" : gt?.mode?.includes("CONTROLLED") ? "custom rule, controlled telemetry" : "custom rule, real action";
  const status = !r.recommendation1 ? "Attempted — no valid recommendation" : r.rehuntFailed ? "Recommendation scored; re-hunt ERROR" : "Evaluated end to end";
  const rec = r.recommendation1 ? `${r.recommendation1.playbook}: ${[...new Set(r.recommendation1.steps.map((s: any) => String(s.action).replace("ACT-", "")))].slice(0, 3).join(", ")}${r.recommendation1.steps.length > 3 ? ", …" : ""} (${r.rescored.compliance})` : "none (validator rejected every attempt)";
  const ver = r.verification ? `${r.verification.result} (REAL_WAZUH)` : r.rehuntFailed ? `ERROR ${r.rehuntFailed.code}` : "not reached";
  P(row(r.caseId, r.attack, `${r.alert.ruleId} (L${r.alert.level}; ${stock})`, (r.alert.mitre ?? []).join(", "), status, rec, ver));
}
P("", "## Table 2 — Main VIGIX evaluation (Real Wazuh, Clean Run v2)", "");
P(row("Metric", "Value", "Numerator / denominator", "Population"), row("---", "---:", "---:", "---"));
const m = metrics;
P(row("Recommendation Compliance", `${m.recommendation_compliance.clean_run__among_evaluated.value}% (among evaluated) · ${m.recommendation_compliance.clean_run__among_attempted.value}% (among attempted)`, "7/7 · 7/9", "validated recommendations · attempted cases"));
P(row("Evidence Coverage", `${m.evidence_coverage.clean_run__per_attempted_case.value}%`, "7/9", "attempted cases"));
P(row("Playbook Alignment", `${m.playbook_alignment.clean_run.value}%`, "7/7", "validated recommendations"));
P(row("Policy Compliance", `${m.policy_compliance.clean_run.value}%`, "7/7", "validated recommendations"));
P(row("Workflow Completion", `${m.workflow_completion.clean_run.value}%`, "5/9", "attempted cases"));
const tm = (s: any) => `mean ${s.mean} s, median ${s.median} s, SD ${s.sd} s, min ${s.min} s, max ${s.max} s`;
P(row("Investigation Time", tm(CL.investigationTime), `n = ${CL.investigationTime.n}`, "cases with a recommendation"));
P(row("Intervention Rate", `${CL.interventionRate.pct}%`, "0/9", "attempted cases (no correction allowed in a Clean Run)"));
P(row("Retry Rate (cases with ≥ 1 retry)", `${CL.retry.caseRatePct}%`, "2/9", `attempted cases; total retry count ${CL.retry.totalRetryCount} (a count, mean ${CL.retry.averagePerCase}/case)`));
P("", "## Table 3 — Clean Run vs Intervention Run (Real Wazuh)", "");
P(row("Metric", "Clean Run", "Intervention Run"), row("---", "---:", "---:"));
P(row("Recommendation Compliance (among evaluated)", "100% (7/7)", "100% (9/9)"));
P(row("Recommendation Compliance (among attempted)", "77.78% (7/9)", "100% (9/9)"));
P(row("Workflow Completion", "55.56% (5/9)", "77.78% (7/9)"));
P(row("Investigation Time", `mean ${CL.investigationTime.mean} s (n=${CL.investigationTime.n}); median ${CL.investigationTime.median}, SD ${CL.investigationTime.sd}`, `mean ${IV.investigationTime.mean} s (n=${IV.investigationTime.n}); median ${IV.investigationTime.median}, SD ${IV.investigationTime.sd}`));
P(row("Detection-to-Response (from VIGIX ingest)", `mean ${CL.detectionToResponse.fromVigixIngest.mean} s (n=${CL.detectionToResponse.fromVigixIngest.n})`, `mean ${IV.detectionToResponse.fromVigixIngest.mean} s (n=${IV.detectionToResponse.fromVigixIngest.n})`));
P(row("Intervention Rate", "0% (0/9)", "22.22% (2/9)"));
P(row("Retry Rate (cases)", `22.22% (2/9); total retries ${CL.retry.totalRetryCount}`, `22.22% (2/9); total retries ${IV.retry.totalRetryCount}`));
P(row("Verification outcomes", "5 RESOLVED, 2 ERROR", "7 RESOLVED, 2 ERROR"));
P("", "The Intervention Run is a different condition (analyst-assisted); it is shown for comparison and is not the system's unaided performance.");

P("", "## Table 4 — Controlled procedural baseline vs VIGIX (comparable measurements only)", "");
const vc = bs.vigix_clean_same_cases;
const vAtk = (k: string) => critCount(k, "attackAlignment");
const meanOf = (xs: number[]) => (xs.length ? r2(xs.reduce((a, b) => a + b, 0) / xs.length) : null);
P(row("Metric", "Baseline (no AI, n = 9)", "VIGIX Clean Run", "VIGIX Intervention Run", "Comparability"), row("---", "---:", "---:", "---:", "---"));
P(row("Case produced a proposed response (coverage)", `${bs.plan_created.numerator}/${bs.plan_created.denominator}`, `${CL.recommendationCompliance.denominator}/9 (valid recommendation)`, `${IV.recommendationCompliance.denominator}/9`, "same population of 9 evaluable cases"));
P(row("Playbook alignment among proposed responses", `${bs.playbook_alignment.numerator}/${bs.playbook_alignment.denominator}`, `${CL.playbookAlignment.numerator}/${CL.playbookAlignment.denominator}`, `${IV.playbookAlignment.numerator}/${IV.playbookAlignment.denominator}`, "same ground truth, same deterministic check"));
P(row("Attack alignment (actions inside the allowed set)", `${bs.attack_alignment.numerator}/${bs.attack_alignment.denominator}`, `${vAtk("real-clean")}/${rows("real-clean").filter((r: any) => r.rescored?.checks).length}`, `${vAtk("real-intervention")}/${rows("real-intervention").filter((r: any) => r.rescored?.checks).length}`, "same ground truth, same deterministic check"));
P(row("Response actions per proposed response (mean)", `${bs.response_action_count.mean} (n=${bs.response_action_count.n})`, `${meanOf(vigixActions("real-clean"))} (n=${vigixActions("real-clean").length})`, `${meanOf(vigixActions("real-intervention"))} (n=${vigixActions("real-intervention").length})`, "count of steps/actions in the proposal"));
P(row("Investigation time (start → proposed response available), mean", `${bt.mean} s (median ${bt.median}, SD ${bt.sd}, n=${bt.n})`, `${CL.investigationTime.mean} s (median ${CL.investigationTime.median}, SD ${CL.investigationTime.sd}, n=${CL.investigationTime.n})`, `${IV.investigationTime.mean} s (median ${IV.investigationTime.median}, SD ${IV.investigationTime.sd}, n=${IV.investigationTime.n})`, "same interval definition; different content (baseline has no LLM stage) — machine latency, not analyst performance"));
P("", "**Not compared (measurements are not comparable):** decision latency (baseline value is NULL: no approval instance and no human; VIGIX's ≈0.06 s is a scripted approval); evidence/indicator counts (VIGIX's incident also holds AI-extracted indicators, the baseline only deterministic ones); policy compliance, approval correctness, verification (the baseline has no Policy/approval/verification stage); required-evidence gating (the baseline treats every extracted indicator as confirmed, VIGIX only evidence-linked or analyst-added ones).");

P("", "## Table 5 — Recommendation consistency (identical evidence, repeated runs)", "");
P(row("Case", "Runs", "Consistent runs", "Consistency %", "Validated runs", "Distinct validated primary recommendations"), row("---", "---:", "---:", "---:", "---:", "---:"));
for (const c of C.perCase) P(row(c.case_id, c.runs, c.consistent_runs, c.consistency_pct, c.validated_runs, c.distinct_primary_recommendations));
P(row("**All cases (pooled)**", ov.runs, ov.consistent_runs, ov.consistency_pct, ov.validated_runs, "–"));
P("", `Per-case mean ${ov.per_case_mean_pct}% (SD ${ov.per_case_sd_pct} percentage points over ${C.perCase.length} cases). Consistent = same playbook, primary action, target type and target value as the modal validated primary recommendation; runs that fail validation count as inconsistent. The evidence snapshot hash was ${ov.all_evidence_snapshots_identical ? "identical in every repetition of every case" : "NOT identical in every repetition (see consistency.json)"}.`);

P("", "## Table 6 — Negative validation (controlled invalid recommendations)", "");
P(row("Scenario", "Invalid condition", "Expected", "Actual", "Validator", "Policy", "Final result"), row(...Array(7).fill("---")));
for (const s of N.scenarios) P(row(`${s.case_id} ${s.scenario}`, s.invalid_condition, s.expected_result, s.actual_result, short(s.validator_result, 60), short(s.policy_result, 60), s.final_status.split(" — ")[0]));
P("", `Unsupported Recommendation Rejection Rate = ${negS.unsupported_recommendation_rejection_rate.numerator}/${negS.unsupported_recommendation_rejection_rate.denominator} = ${negS.unsupported_recommendation_rejection_rate.pct}% (${layerText}); ${negS.rejected_with_expected_code.numerator}/${negS.rejected_with_expected_code.denominator} were rejected with the expected violation code. Each scenario's unmodified candidate first validated (positive control), so each rejection is attributable to the injected fault.`);
P("", "### Table 6b — Human-decision and governance gates (real use cases, cloned database)", "");
P(row("Check", "Scenario", "Expected", "Actual", "Result"), row("---", "---", "---", "---", "---"));
for (const g of gates) P(row(g.id, g.scenario, g.expected, short(String(g.actual), 70), g.pass ? "PASS" : "**FAIL**"));
P("", `Governance gate checks passed: ${negS.governance_gates.passed}/${negS.governance_gates.total}.`);
fs.writeFileSync(path.join(ADD, "paper-results.md"), T.join("\n"));

// ------------------------------------------------------------------ figure-captions.md
const cap: string[] = ["# Figure captions", ""];
const cP = (s: string) => cap.push(s, "");
cP(`**Figure 1.** Main evaluation metrics of the Real Wazuh Clean Run (n = 9 attempted cases; 7 produced a validated recommendation; TC-05 unavailable). For each metric the first bar uses all attempted cases as denominator, the second (where defined) uses only validated recommendations. Recommendation Compliance is a deterministic six-criterion score, not accuracy; Workflow Completion means all workflow steps were recorded through a stored verification, not that the incident was resolved. Results apply only to the 10 predefined test cases.`);
cP(`**Figure 2.** Recommendation Compliance and Workflow Completion (percentage of attempted cases) for the Clean Run (no correction allowed) and the Intervention Run (a scripted analyst corrected IOCs in 2 of 9 cases), n = 9 each. The Intervention Run is a different, analyst-assisted condition and is not the unaided performance of the system.`);
cP(`**Figure 3.** Investigation time (start of investigation to availability of a proposed response) on a logarithmic scale for a controlled procedural baseline (deterministic lookup, no AI, no human; n = ${bt.n}), VIGIX Clean Run (n = ${CL.investigationTime.n}) and VIGIX Intervention Run (n = ${IV.investigationTime.n}). Bars are means, dots are individual cases; median, SD, minimum and maximum are annotated. The baseline is a machine procedure latency without an LLM stage, not an analyst benchmark; no statistical significance is implied.`);
cP(`**Figure 4.** Recommendation consistency across ${C.repetitions} repetitions of the recommendation pipeline on identical evidence snapshots for ${C.perCase.length} representative attack cases (${C.perCase.map((c: any) => c.case_id).join(", ")}). Consistency is the share of runs whose validated primary recommendation (playbook, primary action, target type and target value) equals the modal one; it is not accuracy. The dashed line is the pooled value over all ${ov.runs} runs. A single language model was used and only these cases were tested.`);
cP(`**Figure 5.** Outcomes of the real Wazuh re-hunt verification for completed (simulated) responses in the Clean Run (n = ${CL.verificationEffectiveness.denominator}), the Intervention Run (n = ${IV.verificationEffectiveness.denominator}) and the recurrence control (n = 1). Only outcomes that occurred are drawn; NOT_CONTAINED occurred only as a flag on the control's NOT_RESOLVED result and SPREAD did not occur. RESOLVED means the verification procedure did not detect the specified recurrence condition within the tested window and is not proof of eradication; ERROR means the re-hunt could not run because no searchable IOC existed.`);
cP(`**Figure 6.** Result of negative validation: number of ${negS.unsupported_recommendation_rejection_rate.denominator} controlled invalid recommendations (each a validated candidate with one injected fault, confirmed by a positive control) that the deterministic validator/Policy checks rejected versus accepted. The scenarios test rule coverage and do not measure the accuracy of the AI.`);
fs.writeFileSync(path.join(ADD, "figure-captions.md"), cap.join("\n"));

// ------------------------------------------------------------------ narrative
const nar: string[] = [];
const N_ = (s: string) => nar.push(s, "");
N_("# Results (draft for the paper)");
N_("Labels: **MEASURED RESULT** = a value read from the recorded data; **INTERPRETATION** = what the value supports; **LIMITATION** = what it does not support.");
N_("## 1. Evaluation setup");
N_(`**MEASURED RESULT.** Ten predefined test cases (TC-01…TC-10) were evaluated on a Real Wazuh pipeline: a Wazuh 4.9.2 manager/indexer with an agent on an isolated Ubuntu endpoint produced the alerts; VIGIX ingested each alert, investigated it, generated an AI recommendation (self-hosted vLLM model vllm-spark-01/gemma4-26b-uncensored) that was validated deterministically, sent through a scripted SOC/IR decision, followed by a simulated manual response and a real re-hunt of the Wazuh Indexer. Nine cases were evaluable; TC-05 (PowerShell) needs a Windows endpoint that does not exist and was not simulated. A Clean Run (no corrections allowed) and an Intervention Run (analyst IOC correction when a recommendation was blocked) were executed. Three additional conditions were measured on a cloned database: a controlled procedural baseline, recommendation consistency and negative validation.`);
N_("**LIMITATION.** Only TC-01, TC-04 and TC-06 use stock Wazuh rules; TC-02, TC-07, TC-09 and TC-10 depend on custom rules written for the evaluation, and TC-03, TC-07, TC-08 and TC-09 use harness-generated telemetry. SOC and IR steps are scripted API calls. The evaluation was conducted on 10 predefined test cases and does not represent all SOC situations.");
N_("## 2. Main results");
N_(`**MEASURED RESULT.** In the Clean Run, ${CL.recommendationCompliance.numerator} of ${CL.recommendationCompliance.denominator} validated recommendations satisfied all six deterministic compliance criteria (Recommendation Compliance = 100% among evaluated recommendations; ${CL.recommendationCompliance.pctOfAttempted}% = 7/9 among attempted cases, because TC-03 and TC-08 produced no valid recommendation). Playbook Alignment and Policy Compliance were 7/7, Evidence Coverage was 7/9 attempted cases (${CL.evidenceCoverage.pctOfAttempted}%), and Workflow Completion was 5/9 (${CL.workflowCompletion.pct}%). Investigation Time had a mean of ${CL.investigationTime.mean} s (median ${CL.investigationTime.median}, SD ${CL.investigationTime.sd}, min ${CL.investigationTime.min}, max ${CL.investigationTime.max}; n = ${CL.investigationTime.n}), Detection-to-Response measured from VIGIX ingest had a mean of ${CL.detectionToResponse.fromVigixIngest.mean} s (n = ${CL.detectionToResponse.fromVigixIngest.n}). The Intervention Rate was 0% and 2 of 9 cases needed at least one retry (total retry count ${CL.retry.totalRetryCount}). In the Intervention Run, Recommendation Compliance was 9/9, Workflow Completion 7/9 (${IV.workflowCompletion.pct}%), Investigation Time mean ${IV.investigationTime.mean} s (n = ${IV.investigationTime.n}), and 2 of 9 cases required an analyst correction.`);
N_("**INTERPRETATION.** Whenever the pipeline produced a recommendation that passed validation, that recommendation met the deterministic criteria; the failures of the pipeline were cases in which no recommendation could be validated (an e-mail and a process/command indicator that were not actionable evidence) or in which the follow-up re-hunt could not run. The validator blocked rather than guessed.");
N_("**LIMITATION.** Recommendation Compliance is a conformance score against a fixed ground truth, not accuracy. The 100% figure excludes the two blocked cases and the Intervention result includes analyst corrections; the playbook-alignment figure was obtained after a selector tie-break defect (TC-09) had been found and fixed in the first real run. One run per condition; no confidence intervals are computed.");
N_("## 3. Baseline comparison");
N_(`**MEASURED RESULT.** A controlled procedural baseline (evidence collection from the same Wazuh alert with the same deterministic indicator extractor, playbook lookup from the alert-declared MITRE techniques, and a static plan of every applicable playbook action) produced a proposed response for ${bs.plan_created.numerator} of ${bs.plan_created.denominator} cases, all aligned with the expected playbook (${bs.playbook_alignment.numerator}/${bs.playbook_alignment.denominator}) and inside the allowed action set (${bs.attack_alignment.numerator}/${bs.attack_alignment.denominator}), with a mean of ${bs.response_action_count.mean} actions per plan. Its procedure latency was ${bt.mean} s on average (median ${bt.median}, SD ${bt.sd}, n = ${bt.n}) compared with ${CL.investigationTime.mean} s (n = ${CL.investigationTime.n}) for VIGIX in the Clean Run and ${IV.investigationTime.mean} s (n = ${IV.investigationTime.n}) in the Intervention Run. Baseline decision latency was not measured (NULL).`);
N_("**INTERPRETATION.** On the criteria that both conditions can be scored on, a static playbook lookup reaches the same conformance as VIGIX and is far faster as a machine procedure, and it produced a plan in the two cases where VIGIX's validator produced none. What the baseline does not provide is the AI analysis and instruction text, or the deterministic gates that VIGIX applies before a recommendation is trusted (evidence-linked or analyst-confirmed targets); the baseline treats every extracted indicator as confirmed.");
N_("**LIMITATION.** The baseline is not a human study and says nothing about analyst performance or real-world response time; its latency excludes any human reaction time and any LLM stage, so it must not be read as a speed-up or as evidence for or against VIGIX. Evidence and indicator counts, policy compliance, approval correctness and verification are not compared because the procedures are not comparable.");
N_("## 4. Recommendation consistency");
N_(`**MEASURED RESULT.** With the same evidence snapshot (identical context hash in every repetition) and ${C.repetitions} repetitions per case, pooled Recommendation Consistency was ${ov.consistency_pct}% (${ov.consistent_runs}/${ov.runs} runs; per-case mean ${ov.per_case_mean_pct}%, SD ${ov.per_case_sd_pct} percentage points across ${C.perCase.length} cases). Per case: ${C.perCase.map((c: any) => `${c.case_id} ${c.consistent_runs}/${c.runs}`).join(", ")}. Agreement on the complete set of validated steps (not only the primary one) was ${ov.step_set_agreement_pct_pooled}% pooled (${C.perCase.map((c: any) => `${c.case_id} ${c.step_set_agreement_pct}%`).join(", ")}). All ${ov.validated_runs} runs produced a validated recommendation. ${C.excluded_infrastructure_failure_count} calls failed because the LLM endpoint was unreachable (a ${"120 s"} timeout followed by connection errors) and were excluded from the denominator, listed in consistency.json and repeated after the endpoint returned. Of ${ipSteps} IP-blocking steps in the repeated runs, ${selfSteps.length} (${selfSteps.join("; ") || "none"}) was aimed at the endpoint's own address, which the six criteria cannot detect.`);
N_("**INTERPRETATION.** The values show how stable the validated primary recommendation is when only the AI stage varies; because the validator constrains actions and targets to recorded evidence, variation is confined to which allowed action or target the model ranks first.");
N_("**LIMITATION.** One model, one provider, one day, representative cases only; earlier recommendations were hidden from the context to reproduce first-round generation; consistency is not correctness and says nothing about other models or attack types.");
N_("## 5. Negative validation");
N_(`**MEASURED RESULT.** ${negS.unsupported_recommendation_rejection_rate.numerator} of ${negS.unsupported_recommendation_rejection_rate.denominator} controlled invalid recommendations were rejected (Unsupported Recommendation Rejection Rate = ${negS.unsupported_recommendation_rejection_rate.pct}%; ${layerText}), each with the expected violation code and each after a positive control showed the unmodified candidate was accepted. In the human-decision checks, an IR rejection moved the ticket to PENDING_MANUAL_DECISION without any execution and without closing the incident; approvals by the SOC role, an AI role or an administrator were denied; starting a response before approval, re-hunting before completion and marking an incident RESOLVED manually were blocked (${negS.governance_gates.passed}/${negS.governance_gates.total} checks passed).`);
N_("**INTERPRETATION.** The deterministic validation and human-decision gates behave as specified for the injected faults: the AI cannot approve, execute or resolve, and an unsupported recommendation does not become a response ticket.");
N_("**LIMITATION.** The scenarios were written by the evaluator, contain one fault each and test rule coverage; a 10/10 rejection rate is expected of a deterministic rule set and is not an estimate of how often the AI proposes unsupported actions (in the Clean Run the validator rejected the AI's own output in 10 generation calls). Only one incident and one reject path were exercised.");
N_("## 6. Verification results");
N_(`**MEASURED RESULT.** Real re-hunt outcomes for completed (simulated) responses were 5 RESOLVED and 2 ERROR in the Clean Run and 7 RESOLVED and 2 ERROR in the Intervention Run; the ERROR cases (TC-02, TC-10) had no searchable IOC. Verification/Re-hunt Time had a mean of ${CL.verificationTime.total.mean} s (n = ${CL.verificationTime.total.n}) and ${IV.verificationTime.total.mean} s (n = ${IV.verificationTime.total.n}). In the recurrence control, repeating the TC-01 attack after the response produced ${ctrl.matchingEvents} matching events, iocRecurrence = ${ctrl.iocRecurrence}, result NOT_RESOLVED; the incident stayed ${ctrl.incidentStatus} and Investigation #2 was opened.`);
N_("**INTERPRETATION.** RESOLVED means the verification procedure did not detect the specified recurrence condition within the tested verification window. The control shows that the procedure is able to detect a recurring indicator.");
N_("**LIMITATION.** RESOLVED is not proof of eradication or containment: responses were simulated, each attack ran once, and only IP, domain, URL and hash indicators can be searched (the TC-08 verification searched only the command-line's domain). The sensitivity control is a single case with a single indicator type.");
N_("## 7. Observed failure and intervention cases");
N_("**MEASURED RESULT.** TC-03 (phishing): the sender e-mail was extracted but not actionable, so `ACT-QUARANTINE-EMAIL` was rejected on every attempt (5 failed generation calls in the Clean Run); an analyst confirmation of the indicators produced a compliant recommendation. TC-08 (suspicious process): the process and command line were not extracted from the auditd-style fields, so `ACT-KILL-PROCESS` (which requires COMMAND_LINE evidence) was blocked; analyst-added indicators unblocked it. TC-02 and TC-10 produced compliant recommendations but could not be verified (no hash/file or host-searchable indicator). TC-07: one step targeted the endpoint's own address and was still counted as evidence-supported.");
N_("**INTERPRETATION.** The observed failures concern evidence extraction and verification scope, not the validator's gating, which prevented recommendations without recorded evidence.");
N_("**LIMITATION.** These are properties of the tested extractor and rules; they were recorded, not repaired, during the Clean Run.");
N_("## 8. Limitations");
N_("The evaluation uses 10 predefined cases (9 evaluable), one run per condition for the Real Wazuh results, one LLM (vllm-spark-01/gemma4-26b-uncensored on a self-hosted vLLM server; an earlier internal note naming OpenRouter was wrong and is corrected in CORRECTIONS.md), scripted SOC/IR actors, simulated responses, harness-generated telemetry for four cases and custom rules for four cases. Time-to-Decision (≈0.06 s) is the latency of a scripted approval and is not a human decision time; no baseline decision latency exists. Timing values include third-party LLM latency. The ML risk score table was empty and was not evaluated. No claim of statistical significance or generalisation beyond the tested cases is made.");
fs.writeFileSync(path.join(ADD, "paper-results-narrative.md"), nar.join("\n"));
console.log("wrote paper-metrics.json, figure-data.json, paper-results.md, figure-captions.md, paper-results-narrative.md");
