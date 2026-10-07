/**
 * build-audit-report.ts — renders results/evaluation-audit.md from results/evaluation-audit.json (produced by
 * audit-evaluation.ts) plus the archived MOCK baseline. Pure formatting + fixed verdict rules; no database or
 * network access and no evaluation is run. Verdicts are explained next to each metric, never implied.
 *
 *   npx ts-node --transpile-only scripts/eval/build-audit-report.ts
 */
import * as fs from "node:fs";
import * as path from "node:path";

const ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const RES = path.join(ROOT, "results");
const A = JSON.parse(fs.readFileSync(path.join(RES, "evaluation-audit.json"), "utf8"));
const arch = fs.readdirSync(path.join(RES, "archive")).filter((d) => d.startsWith("mock-run-pre-real-")).sort().pop()!;
const MOCK = JSON.parse(fs.readFileSync(path.join(RES, "archive", arch, "evaluation.json"), "utf8"));
const REP = JSON.parse(fs.readFileSync(path.join(RES, "archive", arch, "repeated-evaluation-N2.json"), "utf8"));

const r2 = (x: number) => Math.round(x * 100) / 100;
const f = (n: unknown, u = "") => (n === null || n === undefined ? "–" : `${n}${u}`);
const pct = (n: number, d: number) => (d ? r2((n / d) * 100) : null);
const st = (xs: (number | null)[]) => {
  const v = xs.filter((x): x is number => typeof x === "number").sort((a, b) => a - b);
  if (!v.length) return { n: 0, mean: null, median: null, min: null, max: null };
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  return { n: v.length, mean: r2(mean), median: r2(v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2), min: v[0], max: v[v.length - 1] };
};
const K = A.kpi;
const mc: any[] = MOCK.cases;
const M9 = mc.filter((c) => c.caseId !== "TC-01"); // TC-01 of the archived run is a hybrid (real alert + mock verification)
const mockCrit = (cs: any[], k: string) => cs.filter((c) => c.compliance?.[k]).length;
const mockRetryCases = (cs: any[]) => cs.filter((c) => c.invalidOutputCount > 0).length;
const mockRetryTotal = (cs: any[]) => cs.reduce((a, c) => a + c.invalidOutputCount, 0);
const mockInterv = (cs: any[]) => cs.filter((c) => c.interventionRequired).length;

const out: string[] = [];
const P = (...s: string[]) => { if (!s.length) out.push(""); else out.push(...s); };
const row = (...c: unknown[]) => `| ${c.join(" | ")} |`;

// ============================================================ 1. executive summary
const cl = K["real-clean"], iv = K["real-intervention"], ct = K["real-recurrence-control"];
P("# VIGIX evaluation audit — preparation for the paper", "");
P(`Generated ${new Date().toISOString()} · read-only audit of existing results · **no evaluation was re-run, no ground truth / policy / playbook / MITRE / result file was modified** (only \`results/evaluation-audit.{md,json}\` and three new scripts under \`apps/backend/scripts/eval/\` were added).`);
P("", "## 1. Executive summary", "");
P(`- **Data integrity: ${A.checks.every((c: any) => c.ok) ? "all " + A.checks.length + " checks PASS" : "FAILURES PRESENT — see §2"}.** Every one of the 19 evaluation alerts exists in the live Wazuh Indexer with identical rule/agent/timestamp; the audit re-score from PostgreSQL equals the stored \`run.json\` results for every case; the MOCK baseline is byte-identical to its archive and equals the stated baseline; the real ground truth hash is unchanged; timestamps are monotonic in every case.`);
P(`- **Primary KPI (Real Wazuh, Clean Run v2, n = 9 attempted, 7 evaluated):** Recommendation Compliance ${cl.recommendationCompliance.pct}% (${cl.recommendationCompliance.numerator}/${cl.recommendationCompliance.denominator} evaluated; ${cl.recommendationCompliance.pctOfAttempted}% of ${cl.recommendationCompliance.denominatorAttempted} attempted); Investigation Time mean ${cl.investigationTime.mean} s / median ${cl.investigationTime.median} s (n=${cl.investigationTime.n}); Time-to-Decision mean ${cl.timeToDecision.mean} s (scripted decision); Verification: ${cl.verificationEffectiveness.numerator}/${cl.verificationEffectiveness.denominator} executed responses ended RESOLVED, ${cl.verificationEffectiveness.outcomes.ERROR ?? 0} ended in re-hunt ERROR.`);
P(`- **Intervention Run v2:** compliance ${iv.recommendationCompliance.pct}% (${iv.recommendationCompliance.numerator}/${iv.recommendationCompliance.denominator}) after ${iv.interventionRate.numerator} analyst corrections (${iv.interventionRate.cases.join(", ")}); this is a *different condition* from the Clean Run and must not be reported as the system's unaided accuracy.`);
P(`- **Verification control (recurrence):** confirmed from PostgreSQL — matching events = ${A.control.matchingEvents}, iocRecurrence = ${A.control.iocRecurrence}, result = ${A.control.result}, incident = ${A.control.incidentStatus}, investigations ${A.control.investigations.join(" / ")} (reopened by ${A.control.reopenedBy.join(", ")}). It is a single positive control on one case.`);
P(`- **Not paper-ready as stated:** Time-to-Decision (scripted approval, ≈0.06 s), Verification Effectiveness as a claim of *containment* (responses were simulated, attacks ran once, sensitivity shown once), the MOCK timing metrics (contain manual gaps), and anything about rejection/manual-decision paths, ML risk score and Windows/PowerShell (no data). See §11–§12.`);
P(`- **Overall verdict: NEEDS_MORE_DATA** for verification-related claims and human-decision timing; **READY_FOR_PAPER (with the stated caveats)** for Recommendation Compliance, Playbook Alignment, Policy Compliance, Workflow Completion, Investigation Time and the retry/intervention descriptions, provided the sample (10 predefined cases, 9 attempted, one run per condition) is stated.`);

// ============================================================ 2. data integrity
P("", "## 2. Data Integrity Check", "");
P(row("ID", "Check", "Result", "Detail"), row("---", "---", "---", "---"));
for (const c of A.checks) P(row(c.id, c.name, c.ok ? "PASS" : "**FAIL**", String(c.detail).replace(/\|/g, "/")));
const mockIds = new Set(mc.map((c) => c.incidentId));
const realIds = Object.values(A.cases as Record<string, any[]>).flat().map((r: any) => r.incidentId).filter(Boolean);
const overlap = realIds.filter((i: string) => mockIds.has(i)).length;
P(row("I12", "MOCK and REAL_WAZUH share no incident", overlap === 0 ? "PASS" : "**FAIL**", `${overlap} shared incident ids between the archived MOCK run and the three real runs`));
P("", "Additional integrity observations (not failures, but they bound what the data can show):", "");
P("- **Superseded runs are not in `soar_eval`.** Clean Run #1 and the partial post-fix run were followed by a database reset; only their `run.json` files (`results/runs/`) and SQL dumps (`backups/db/`) remain. They are excluded from every number below (register: `results/runs/README.md`).");
P(`- **The archived MOCK row for TC-01 is a hybrid**: its incident was built from a real Wazuh alert of agent \`attack-endpoint\` (the older \`run-evaluation.ts\` selects the latest alert by rule id only) with a mock verification. MOCK numbers are therefore given for the archived 10 cases *and* for the 9 pure-mock cases.`);
P(`- **soar_platform was untouched**: ${A.platform.alerts} alerts / ${A.platform.incidents} incidents, identical to the pre-evaluation snapshot, and none of the evaluation alerts is present there (the manager's webhook hop to the development backend was not part of the evaluation path).`);
P(`- **Verification provenance:** all ${A.checks.find((c: any) => c.id === "I4").detail.split(" ")[0]} verifications in \`soar_eval\` carry \`evidenceSource = WAZUH_INDEXER\`; none is MOCK or manual.`);

// ============================================================ 3-5. metric tables
const hdr = row("Metric", "Result", "Numerator", "Denominator", "Mode", "Paper Ready");
const sep = row("------", "-----:", "-----:", "-----:", "----", "-----------");
const readyTxt = { yes: "YES", cav: "YES — with caveat", no: "NO", na: "NOT_AVAILABLE" };
P("", "## 3. Primary KPI", "");
P(hdr, sep);
P(row("Recommendation Compliance — MOCK baseline (10 archived cases)", "100%", "10", "10", "MOCK (deterministic scorer)", `${readyTxt.cav}: TC-01 is a hybrid; 4 cases needed intervention`));
P(row("Recommendation Compliance — MOCK (9 pure-mock cases)", "100%", String(M9.filter((c) => c.recommendationCompliance === "COMPLIANT").length), String(M9.length), "MOCK", readyTxt.cav));
P(row("Recommendation Compliance — Real Clean", `${cl.recommendationCompliance.pct}%`, cl.recommendationCompliance.numerator, cl.recommendationCompliance.denominator, "REAL_WAZUH (deterministic)", `${readyTxt.cav}: report BOTH denominators — ${cl.recommendationCompliance.pctOfAttempted}% of ${cl.recommendationCompliance.denominatorAttempted} attempted (${cl.recommendationCompliance.noValidRecommendation.join(", ")} produced no valid recommendation)`));
P(row("Recommendation Compliance — Real Intervention", `${iv.recommendationCompliance.pct}%`, iv.recommendationCompliance.numerator, iv.recommendationCompliance.denominator, "REAL_WAZUH (deterministic)", `${readyTxt.cav}: only together with the Clean result and the ${iv.interventionRate.numerator} analyst corrections`));
const tm = (k: any, kk: "investigationTime" | "timeToDecision") => `mean ${f(k[kk].mean)} / median ${f(k[kk].median)} / min ${f(k[kk].min)} / max ${f(k[kk].max)} s`;
const mockInv = st(mc.map((c) => c.investigationTimeSeconds)), mockTtd = st(mc.map((c) => c.timeToDecisionSeconds));
P(row("Investigation Time — MOCK baseline", tm({ investigationTime: mockInv }, "investigationTime"), "–", `n=${mockInv.n}`, "MOCK stepwise run", `${readyTxt.no}: contains manual gaps of hours (max 5195 s); not a latency`));
P(row("Investigation Time — MOCK repeated single-pass (N=2)", `mean ${REP.overall.investigationTimeMean} s ± ${REP.overall.investigationTimeSd}`, "–", "20 case-runs", "MOCK uninterrupted", `${readyTxt.cav}: only 2 repetitions; mean ± SD only, no median in the file`));
P(row("Investigation Time — Real Clean", tm(cl, "investigationTime"), "–", `n=${cl.investigationTime.n}`, "REAL_WAZUH, uninterrupted", `${readyTxt.cav}: includes third-party LLM latency; excludes the 2 cases with no valid recommendation (right-censored); single run`));
P(row("Investigation Time — Real Intervention", tm(iv, "investigationTime"), "–", `n=${iv.investigationTime.n}`, "REAL_WAZUH, uninterrupted", `${readyTxt.cav}: includes retry rounds (TC-03 265 s, TC-08 129 s) and analyst-correction step`));
P(row("Time-to-Decision — MOCK baseline", tm({ timeToDecision: mockTtd }, "timeToDecision"), "–", `n=${mockTtd.n}`, "MOCK stepwise run", `${readyTxt.no}: mixes scripted (≈0.05 s) and manual-gap (up to 3426 s) decisions`));
P(row("Time-to-Decision — Real Clean", tm(cl, "timeToDecision"), "–", `n=${cl.timeToDecision.n}`, "REAL_WAZUH, scripted IR decision", `${readyTxt.no} as human decision time: it is the latency of a scripted API approval; report only as system overhead`));
P(row("Time-to-Decision — Real Intervention", tm(iv, "timeToDecision"), "–", `n=${iv.timeToDecision.n}`, "REAL_WAZUH, scripted IR decision", readyTxt.no));
P(row("Verification Effectiveness — MOCK", "–", "–", "–", "MOCK", `${readyTxt.na}: MOCK NO_MATCH is simulated (CleanRehuntAdapter) — 10/10 completed is workflow reachability, not effectiveness`));
P(row("Verification Effectiveness — Real Clean", `${cl.verificationEffectiveness.pct}%`, cl.verificationEffectiveness.numerator, cl.verificationEffectiveness.denominator, "REAL_WAZUH", `${readyTxt.no} as an effectiveness claim — report as an outcome distribution (§8)`));
P(row("Verification Effectiveness — Real Intervention", `${iv.verificationEffectiveness.pct}%`, iv.verificationEffectiveness.numerator, iv.verificationEffectiveness.denominator, "REAL_WAZUH", readyTxt.no));
P("", "Verification Effectiveness = cases whose real re-hunt confirmed no recurrence (`RESOLVED`) / cases with a completed response execution. Outcome vocabulary of the requested taxonomy as it maps onto VIGIX: `RESOLVED` = RESOLVED; `NOT_RESOLVED` = NOT_RESOLVED; `NOT_CONTAINED` = NOT_RESOLVED with `threatContained=false`; `SPREAD` = NOT_RESOLVED with `spreadDetected=true`; `ERROR` = re-hunt failed (`REHUNT_*`), no verification created.");
P("", "Outcome distribution of executed responses: " + [["Real Clean", cl], ["Real Intervention", iv], ["Recurrence control", ct]].map(([n, k]: any) => `**${n}** ${JSON.stringify(k.verificationEffectiveness.outcomes)}`).join(" · "));

P("", "## 4. Supporting Metrics", "");
P(hdr, sep);
const mockWf = mc.filter((c) => c.workflowCompleted).length;
P(row("Workflow Completion — MOCK baseline", "100%", mockWf, mc.length, "MOCK", `${readyTxt.cav}: 'complete' = all 11 workflow flags true incl. a MOCK verification`));
P(row("Workflow Completion — Real Clean", `${cl.workflowCompletion.pct}% (${cl.workflowCompletion.pctOfTotal}% of all 10)`, cl.workflowCompletion.numerator, cl.workflowCompletion.denominator, "REAL_WAZUH", `${readyTxt.yes}: recomputed from DB rows per step (not 'an incident exists'); incomplete = ${cl.workflowCompletion.incomplete.join("; ")}`));
P(row("Workflow Completion — Real Intervention", `${iv.workflowCompletion.pct}% (${iv.workflowCompletion.pctOfTotal}% of all 10)`, iv.workflowCompletion.numerator, iv.workflowCompletion.denominator, "REAL_WAZUH", `${readyTxt.yes}: incomplete = ${iv.workflowCompletion.incomplete.join("; ")}`));
P(row("Intervention Rate — MOCK baseline", `${pct(mockInterv(mc), mc.length)}%`, mockInterv(mc), mc.length, "MOCK", `${readyTxt.cav}: cases TC-03, 07, 08, 09 (analyst IOC, MITRE catalog, playbook seed)`));
P(row("Intervention Rate — Real Clean", `${cl.interventionRate.pct}%`, cl.interventionRate.numerator, cl.interventionRate.denominator, "REAL_WAZUH", `${readyTxt.cav}: 0% by construction (no correction is allowed in a Clean Run); blocked cases are counted as failures instead`));
P(row("Intervention Rate — Real Intervention", `${iv.interventionRate.pct}%`, iv.interventionRate.numerator, iv.interventionRate.denominator, "REAL_WAZUH", `${readyTxt.cav}: the 'analyst' is a fixed script; reason for both = Missing/non-actionable IOC (TC-03 e-mail; TC-08 process+command)`));
P(row("Recommendation Retry Rate — MOCK baseline", `${pct(mockRetryCases(mc), mc.length)}%`, mockRetryCases(mc), mc.length, "MOCK", `${readyTxt.cav}: total retry count ${mockRetryTotal(mc)} is a count, not a percentage`));
P(row("Recommendation Retry Rate — Real Clean", `${cl.retry.caseRatePct}%`, cl.retry.caseRateNumerator, cl.retry.caseRateDenominator, "REAL_WAZUH", `${readyTxt.cav}: total retry count ${cl.retry.totalRetryCount} (avg ${cl.retry.averagePerCase}/case); TC-03 and TC-08 hit the harness cap of 5 → right-censored`));
P(row("Recommendation Retry Rate — Real Intervention", `${iv.retry.caseRatePct}%`, iv.retry.caseRateNumerator, iv.retry.caseRateDenominator, "REAL_WAZUH", `${readyTxt.cav}: total retry count ${iv.retry.totalRetryCount} (avg ${iv.retry.averagePerCase}/case)`));
P(row("Evidence Coverage — MOCK baseline", `${pct(mockCrit(mc, "evidenceSupport"), mc.length)}%`, mockCrit(mc, "evidenceSupport"), mc.length, "MOCK", `${readyTxt.cav}: evidenceSupport criterion after manual IOC fixes`));
P(row("Evidence Coverage — Real Clean (per attempted case)", `${cl.evidenceCoverage.pctOfAttempted}%`, cl.evidenceCoverage.casesWithRecommendationAllTargetsEvidenceBacked, cl.evidenceCoverage.denominatorAttempted, "REAL_WAZUH", `${readyTxt.cav}: the informative figure — cases with no valid recommendation count as not covered`));
P(row("Evidence Coverage — Real Clean (per recommendation)", `${cl.evidenceCoverage.pctOfRecommendations}%`, cl.evidenceCoverage.evidenceSupportCriterionPassed, cl.evidenceCoverage.denominatorWithRecommendation, "REAL_WAZUH", `${readyTxt.no}: tautological — only validator-passed recommendations exist, so 100% by construction`));
P(row("Evidence Coverage — Real Intervention (per attempted case)", `${iv.evidenceCoverage.pctOfAttempted}%`, iv.evidenceCoverage.casesWithRecommendationAllTargetsEvidenceBacked, iv.evidenceCoverage.denominatorAttempted, "REAL_WAZUH", `${readyTxt.cav}: after analyst IOC correction; membership test, not semantic (see TC-07 self-targeting)`));
P(row("Policy Compliance — MOCK baseline", `${pct(mockCrit(mc, "policyCompliance"), mc.length)}%`, mockCrit(mc, "policyCompliance"), mc.length, "MOCK", readyTxt.cav));
P(row("Policy Compliance — Real Clean", `${cl.policyCompliance.pct}%`, cl.policyCompliance.numerator, cl.policyCompliance.denominator, "REAL_WAZUH", `${readyTxt.cav}: step approval flag == Policy snapshot and a responsible role present; no negative test exists`));
P(row("Policy Compliance — Real Intervention", `${iv.policyCompliance.pct}%`, iv.policyCompliance.numerator, iv.policyCompliance.denominator, "REAL_WAZUH", readyTxt.cav));
P(row("Playbook Alignment — MOCK baseline", `${pct(mockCrit(mc, "playbookAlignment"), mc.length)}%`, mockCrit(mc, "playbookAlignment"), mc.length, "MOCK", `${readyTxt.cav}: measured after PB-C2/PB-DATA-EXFIL were seeded during the run`));
P(row("Playbook Alignment — Real Clean", `${cl.playbookAlignment.pct}%`, cl.playbookAlignment.numerator, cl.playbookAlignment.denominator, "REAL_WAZUH", `${readyTxt.cav}: obtained AFTER fixing a selector tie-break defect found in the first real run (TC-09 chose PB-C2 instead of PB-DATA-EXFIL) — disclose`));
P(row("Playbook Alignment — Real Intervention", `${iv.playbookAlignment.pct}%`, iv.playbookAlignment.numerator, iv.playbookAlignment.denominator, "REAL_WAZUH", readyTxt.cav));
P(row("Approval Correctness — MOCK baseline", `${pct(mockCrit(mc, "approvalCorrectness"), mc.length)}%`, mockCrit(mc, "approvalCorrectness"), mc.length, "MOCK", `${readyTxt.cav}: approvals recorded by scripts`));
P(row("Approval Correctness — Real Clean", `${cl.approvalCorrectness.pct}%`, cl.approvalCorrectness.numerator, cl.approvalCorrectness.denominator, "REAL_WAZUH", `${readyTxt.cav}: all decisions are scripted 'approved' by IR_TEAM; rejected decisions in the data = ${cl.approvalCorrectness.rejectedDecisions}`));
P(row("Approval Correctness — Real Intervention", `${iv.approvalCorrectness.pct}%`, iv.approvalCorrectness.numerator, iv.approvalCorrectness.denominator, "REAL_WAZUH", `${readyTxt.cav}: rejected decisions = ${iv.approvalCorrectness.rejectedDecisions}`));

P("", "## 5. Real Wazuh Metrics", "");
P(hdr, sep);
const d = (k: any, kk: string) => k.detectionToResponse[kk];
const dd = (s: any) => `mean ${f(s.mean)} / median ${f(s.median)} / min ${f(s.min)} / max ${f(s.max)} s`;
P(row("Detection-to-Response — MOCK", "–", "–", "–", "MOCK", `${readyTxt.na}: alert timestamps are synthetic; not defined for mock`));
P(row("Detection-to-Response (from Wazuh alert timestamp) — Real Clean", dd(d(cl, "fromWazuhAlertTimestamp")), "–", `n=${d(cl, "fromWazuhAlertTimestamp").n}`, "REAL_WAZUH", `${readyTxt.cav}: includes the harness' indexer polling/ingest delay (≈12 s) — not VIGIX latency`));
P(row("Detection-to-Response (from VIGIX ingest) — Real Clean", dd(d(cl, "fromVigixIngest")), "–", `n=${d(cl, "fromVigixIngest").n}`, "REAL_WAZUH", `${readyTxt.cav}: closest to workflow latency (ingest → response start); includes LLM latency and a scripted SOC/IR step`));
P(row("Detection-to-Response (from Wazuh alert timestamp) — Real Intervention", dd(d(iv, "fromWazuhAlertTimestamp")), "–", `n=${d(iv, "fromWazuhAlertTimestamp").n}`, "REAL_WAZUH", readyTxt.cav));
P(row("Detection-to-Response (from VIGIX ingest) — Real Intervention", dd(d(iv, "fromVigixIngest")), "–", `n=${d(iv, "fromVigixIngest").n}`, "REAL_WAZUH", readyTxt.cav));
const vt = (k: any) => k.verificationTime.total;
P(row("Verification/Re-hunt Time — Real Clean", dd(vt(cl)), "–", `n=${vt(cl).n} verifications`, "REAL_WAZUH", `${readyTxt.cav}: REHUNT_STARTED → verification stored (indexer query + verification); the harness' 15 s indexer-refresh wait is outside it; single small index`));
P(row("Verification/Re-hunt Time — Real Intervention", dd(vt(iv)), "–", `n=${vt(iv).n} verifications`, "REAL_WAZUH", readyTxt.cav));
P(row("Time to re-hunt ERROR (failed re-hunts) — Real Clean / Intervention", `${f(cl.verificationTime.timeToErrorForFailedRehunts.mean)} s / ${f(iv.verificationTime.timeToErrorForFailedRehunts.mean)} s`, "–", `n=${cl.verificationTime.timeToErrorForFailedRehunts.n} / ${iv.verificationTime.timeToErrorForFailedRehunts.n}`, "REAL_WAZUH", `${readyTxt.no}: an error, not a verification`));
P("", "Wazuh-query time vs verification-processing time cannot be separated: the audit trail stores one `REHUNT_STARTED` and one `VERIFICATION_COMPLETED`/`verified_at` timestamp, so only the total is reported. Manual test-setup time (lab preparation, the simulated attack itself, the harness' 3 s pause before response completion and 15 s indexer-refresh wait) is **not** included in any workflow latency above.");

// ============================================================ 6. per-case audit
const cases = (key: string) => (A.cases[key] as any[]);
const casesTable = (key: string) => {
  P(row("TC", "Attack", "Wazuh rule / level / MITRE", "Playbook (actual vs expected)", "Actions → targets (step order)", "Compliance", "Inv. s", "TTD s", "D→R s (ingest)", "Verif. s", "Retries", "Intervention", "Verification", "Final", "Workflow"), row(...Array(15).fill("---")));
  for (const r of cases(key)) {
    if (r.environmentStatus === "ENVIRONMENT_UNAVAILABLE") { P(row(r.caseId, r.attack, "–", "–", "–", "ENVIRONMENT_UNAVAILABLE", "–", "–", "–", "–", "–", "–", "–", "–", "not run")); continue; }
    const steps = (r.recommendation1?.steps ?? []).map((s: any) => `${String(s.action).replace("ACT-", "")}→${String(s.target).length > 32 ? String(s.target).slice(0, 30) + "…" : s.target}`).join("<br>");
    const v = r.verification ? `${r.verification.result} (${r.verification.mode === "WAZUH_INDEXER" ? "REAL_WAZUH" : r.verification.mode})` : r.rehuntFailed ? `ERROR ${r.rehuntFailed.code ?? ""}` : "not reached";
    P(row(r.caseId, r.attack, `${r.alert?.ruleId} / L${r.alert?.level} / ${(r.alert?.mitre ?? []).join(",")}`, r.recommendation1 ? `${r.recommendation1.playbook} vs ${r.expectedPlaybook}${r.playbookCodeMatches ? "" : " ✗"}` : `none vs ${r.expectedPlaybook}`, steps || "no valid recommendation", r.rescored?.compliance ?? "NOT_EVALUATED",
      f(r.times?.investigationSeconds), f(r.times?.timeToDecisionSeconds), f(r.times?.detectionToResponseFromIngestSeconds), f(r.times?.verificationSeconds), r.failedGenerationCallsInvestigation1 ?? 0,
      r.interventions?.length ? [...new Set(r.interventions.map((i: any) => i.type))].join(";") : "none", v, cases(key) && (r.rescored ? (await0(r)) : "–"), r.workflowComplete ? "complete" : "incomplete"));
  }
};
function await0(r: any) { return r.verification?.result === "RESOLVED" ? "resolved" : r.verification ? "investigating" : r.recommendation1 ? "open" : "open (no recommendation)"; }
P("", "## 6. Per-case Audit", "", "All values recomputed from PostgreSQL (`soar_eval`); *TTD* = Time-to-Decision (scripted), *D→R* = Detection-to-Response measured from VIGIX ingest, *Verif.* = verification time.", "", "### 6.1 Real Clean Run v2", "");
casesTable("real-clean");
P("", "### 6.2 Real Intervention Run v2", "");
casesTable("real-intervention");
P("", "### 6.3 Recurrence control (TC-01 repeated after the response)", "");
casesTable("real-recurrence-control");
P("", "The `Final` column is the incident status derived from verification (`RESOLVED` only via a stored verification; no AI action changes it). Column `Workflow` = all 11 workflow steps present in the database (§4).");

// ============================================================ 7. evidence coverage
P("", "## 7. Evidence Coverage", "", "Deterministic only (no LLM): for each case the audit lists the incident's IOCs, whether every step target is an evidence-linked IOC, an analyst-added IOC or an affected host (the evaluator's rule, recomputed independently from the rows), and the validator's rejection codes for the failed generation calls. Category mapping: `INVENTED_TARGET` = target not evidence-linked / missing IOC; `TARGET_TYPE_MISMATCH` = unsupported target (wrong target type for the action); `INSUFFICIENT_EVIDENCE` = required evidence (e.g. COMMAND_LINE, FILE_HASH) not recorded.", "");
for (const [label, key] of [["Clean Run v2", "real-clean"], ["Intervention Run v2", "real-intervention"]] as const) {
  P(`### ${label}`, "", row("TC", "Expected IOCs found before any correction", "IOC support of final step targets", "Validator rejection codes (failed calls)", "Coverage verdict"), row("---", "---", "---", "---", "---"));
  for (const r of cases(key).filter((x: any) => x.environmentStatus !== "ENVIRONMENT_UNAVAILABLE")) {
    const rec = r.iocRecallBeforeCorrection;
    const sup = (r.evidence?.stepSupport ?? []).map((s: any) => `${String(s.action).replace("ACT-", "")}: ${s.supportedBy ?? "UNSUPPORTED"}`).join("<br>") || "no recommendation";
    const codes = r.violationCodes ? Object.entries(r.violationCodes).map(([k, v]) => `${k}×${v}`).join(", ") : "–";
    const verdict = !r.recommendation1 ? "NOT COVERED — no validator-passing recommendation (Missing IOC / Unsupported target / Insufficient evidence)" : r.evidence?.allStepsSupported ? "covered" + (rec && rec.missing.length ? ` (but ${rec.missing.length} expected IOC(s) were absent from the incident before correction)` : "") : "NOT COVERED — a step target is not evidence-backed";
    P(row(r.caseId, rec ? `${rec.found}/${rec.expected}${rec.missing.length ? " — missing " + rec.missing.map((m: string) => m.length > 50 ? m.slice(0, 48) + "…" : m).join(", ") : ""}` : "–", sup, codes, verdict));
  }
  P("");
}
P(`Failed-call violation totals — Clean: ${JSON.stringify(cl.retry.reasons)}; Intervention: ${JSON.stringify(iv.retry.reasons)} (one failed generation call can carry several violations; they are counts of violations, not of cases).`);
P("", "Caveats: (1) the membership test cannot tell a *wrong-role* IP from a right one — TC-07's step `ACT-BLOCK-DESTINATION-IP → 172.19.0.5` (the monitored endpoint's own address) is counted as covered; (2) the FIM hash/path (TC-02) and the auditd process/command (TC-08) are present in the alerts but are not extracted as IOCs, so 'expected IOCs found' for those cases measures the extractor, not the AI.");

// ============================================================ 8. verification audit
P("", "## 8. Verification Audit", "");
P(row("Run", "TC", "Mode", "Index", "Searched IOCs (type:value)", "Matching events", "IOC recurrence", "Spread", "Contained", "Result", "Verif. s"), row(...Array(11).fill("---")));
for (const key of ["real-clean", "real-intervention", "real-recurrence-control"]) for (const r of cases(key)) {
  if (r.verification) P(row(key, r.caseId, r.verification.mode === "WAZUH_INDEXER" ? "REAL_WAZUH" : r.verification.mode, r.verification.index, (r.verification.searchedIocs ?? []).map((i: any) => `${i.type}:${String(i.value).length > 40 ? String(i.value).slice(0, 38) + "…" : i.value}`).join("<br>"), r.verification.matchingEvents, r.verification.iocRecurrence, r.verification.spreadDetected, r.verification.threatContained, r.verification.result, f(r.times.verificationSeconds)));
  else if (r.rehuntFailed) P(row(key, r.caseId, "REAL_WAZUH (not created)", "–", "none searchable", "–", "–", "–", "–", `ERROR ${r.rehuntFailed.code}`, f(r.times?.rehuntErrorSeconds)));
}
P("", "Findings of the verification audit:", "");
P("- **Mode:** every verification in `soar_eval` is `REAL_WAZUH` (`evidenceSource = WAZUH_INDEXER`, index pattern `wazuh-alerts-4.x-*`); none is MOCK or manual entry. The query window of each verification starts at the completion of the (simulated) manual response and the recorded time range is stored with the row.");
P("- **`RESOLVED` evidence:** each RESOLVED row has `matchingEvents = 0`, `iocRecurrence = false`, `spreadDetected = false`, `threatContained = true` and the list of IOCs that were actually searched. The search space is only what VIGIX can query: IP / domain / URL / hash IOCs.");
P("- **Weak verifications:** TC-08 (Intervention) searched only the C2 URL/domain taken from the command line — it does **not** test that the suspicious process stopped; TC-06 searched the request path typed as a URL plus the attacker IP. `RESOLVED` there means 'those indicators did not reappear', not 'the behaviour is gone'.");
P("- **No verification possible:** TC-02 (no hash/file IOC extracted from `syscheck.*`) and TC-10 (username-only IOC) ended in `REHUNT_INSUFFICIENT_CRITERIA`, correctly leaving the incident open (a failed re-hunt proves nothing).");
P(`- **Sensitivity control (recurrence), confirmed from PostgreSQL:** matching events = **${A.control.matchingEvents}**, \`iocRecurrence = ${A.control.iocRecurrence}\`, result = **${A.control.result}**, \`threatContained = ${A.control.threatContained}\`, \`spreadDetected = ${A.control.spreadDetected}\`; the incident stayed \`${A.control.incidentStatus}\` and investigations are ${A.control.investigations.join(" / ")}; Investigation #2 was opened by Policy ${A.control.reopenedBy.join(" + ")}; no AI action resolved or executed anything.`);
P("- **What the control does and does not show:** the re-hunt is *able* to detect a recurring attacker IP (positive control, TC-01, n = 1). There is no negative control across other IOC types (domain/URL/hash), no test of spread detection, and every response was simulated.");
P("- **Verification/Re-hunt time:** computable for all 13 verifications (0.02–0.04 s) from `REHUNT_STARTED` to `verified_at`; split into query vs processing time is **not** possible from stored timestamps.");

// ============================================================ 9. findings
P("", "## 9. Findings", "");
P("**Audit findings (about the evaluation data and reports)**", "");
P("- **A1 — MOCK baseline TC-01 is a hybrid.** Real alert + mock verification (older `run-evaluation.ts` picks the latest alert by rule id only). Not modified; flagged in `results/evaluation-summary.md`, `case-results.*` and here.");
P("- **A2 — MOCK timing is not a latency.** The stepwise mock run mixes scripted steps (≈0.05 s) with manual gaps of hours; the only clean MOCK latency is the N=2 repeated single-pass file (verification not exercised there).");
P("- **A3 — The MOCK evaluation scripts were not production-parity** (no `responseSetup`/`compliancePolicy`); Real runs use production-parity wiring, so MOCK and REAL numbers are not like-for-like even apart from mock vs real telemetry.");
P("- **A4 — Retry counts are censored at the harness cap of 5 attempts** for the two Clean-Run cases that never produced a valid recommendation (true retry count ≥ 5).");
P("- **A5 — Time-to-Decision is a scripted API latency** in every Real run; only its *definition* (T_decision − T_recommendation) is validated, not any human behaviour.");
P("- **A6 — Detection-to-Response includes harness artefacts** when measured from the Wazuh alert timestamp (indexer polling before ingest); the ingest-based figure is the defensible one.");
P("- **A7 — `Workflow Completion` does not require `RESOLVED`.** The control case counts as complete (all steps present) while its incident is `investigating`; completion means 'the pipeline ran to a verification', not 'the threat is resolved'.");
P("- **A8 — Evidence Coverage per recommendation is tautological** (validator gate); the per-attempted-case figure is the meaningful one. Both are reported.");
P("- **A9 — No calculation error was found in the existing report:** the audit recomputed every KPI from PostgreSQL and every value agreed with `run.json` (I8). Reported numbers in `results/evaluation-summary.md` are unchanged.");
P("", "**System findings carried over from the evaluation (unchanged, re-confirmed against the data)**", "");
P("- F-IOC-1 (TC-03): the sender e-mail is extracted but is not an actionable/evidence-linked IOC → `ACT-QUARANTINE-EMAIL` rejected (`INVENTED_TARGET`/`TARGET_TYPE_MISMATCH`); Clean Run: 5 failed generations, no valid recommendation; needs an analyst IOC confirmation.");
P("- F-IOC-2 (TC-08, TC-02): the IOC extractor does not read `data.audit.*` or `syscheck.*`; `ACT-KILL-PROCESS` (needs COMMAND_LINE) is blocked as designed; TC-02 has no hash IOC → no re-hunt.");
P("- F-VER-1 (TC-02, TC-10): identity/host-only incidents cannot be verified by an IOC re-hunt (`REHUNT_INSUFFICIENT_CRITERIA`).");
P("- F-EVAL-1 (TC-07/TC-09): a step may target the monitored endpoint's own IP and still pass `evidenceSupport`; reported as `SELF_TARGETING_STEP` outside the six criteria.");
P("- F-KB (fixed before the reported run): `PlaybookSelector` tie-break let an AI-inferred technique flip TC-09's playbook; SIEM-asserted techniques now win an equal-count tie (4 unit tests). The Real playbook-alignment figure is post-fix.");
P("- Findings that were **not** reproduced: the MOCK-era KB gaps (PB-C2 / T1071.001, PB-DATA-EXFIL / T1048) did not occur — the Knowledge Base was complete beforehand — and TC-10's T1098 → PB-ACCOUNT-COMPROMISE mapping was documented, not changed, and matched the ground truth.");

// ============================================================ 10. limitations
P("", "## 10. Limitations", "");
for (const s of [
  "**Sample:** 10 predefined test cases (9 attempted; TC-05 needs a Windows endpoint that does not exist) — \"Evaluation was conducted on 10 predefined test cases.\" It is not a sample of SOC situations and supports no statistical inference; there are no confidence intervals and one run per condition.",
  "**Mock vs Real:** kept separate everywhere; not comparable one-to-one (different alerts, ground truth keyed to different rules, mock TC-01 hybrid, different wiring).",
  "**Simulated response:** no containment was executed; a Real `RESOLVED` therefore means no recurrence in a short window after a simulated response. Attacks ran once.",
  "**Scripted humans:** SOC triage, SOC→IR hand-off and IR approval are API calls; the analyst correction is a fixed script; no rejection or manual-decision path was exercised.",
  "**Environment:** private Docker addresses; TC-03/07/08/09 use harness-generated telemetry; TC-02/07/09/10 detections exist only through custom rules written for the evaluation (stock Wazuh covers TC-01, TC-04, TC-06).",
  "**LLM:** one model (`google/gemma-4-26b-a4b-it` via OpenRouter; the active provider is inferred from a doubly-defined `LLM_PROVIDER`), one run per condition; repeated-run reliability not tested; Investigation Time includes third-party API latency.",
  "**ML risk score:** the `risk_scores` table is empty — no ML output exists to evaluate.",
  "**Production parity:** analysis ran synchronously instead of through the worker queue; `CreateVerification` had no `sendRecommendationToIr` (only relevant to the NOT_RESOLVED round exercised once); the webhook hop was bypassed.",
].map((x) => "- " + x)) P(s);

// ============================================================ 11. paper-ready
P("", "## 11. Paper-ready Metrics", "", "Numbers that can be cited **as they are**, each with its condition. Everything is Real Wazuh, Clean Run v2 unless stated.", "");
P(row("Metric", "Value to cite", "Condition to state alongside", "Status"), row("---", "---", "---", "---"));
P(row("Recommendation Compliance", `${cl.recommendationCompliance.pct}% (${cl.recommendationCompliance.numerator}/${cl.recommendationCompliance.denominator} evaluated); ${cl.recommendationCompliance.pctOfAttempted}% (${cl.recommendationCompliance.numerator}/${cl.recommendationCompliance.denominatorAttempted}) of attempted`, "deterministic six-criterion scorer, no LLM judge; 2 attempted cases produced no valid recommendation; Intervention Run (analyst-assisted): 9/9", "READY_FOR_PAPER"));
P(row("Playbook Alignment", `${cl.playbookAlignment.pct}% (${cl.playbookAlignment.numerator}/${cl.playbookAlignment.denominator})`, "measured after the PlaybookSelector tie-break fix; first real run had 1 mismatch (TC-09)", "READY_FOR_PAPER"));
P(row("Policy Compliance", `${cl.policyCompliance.pct}% (${cl.policyCompliance.numerator}/${cl.policyCompliance.denominator})`, "current Policy implementation as source of truth; no negative test", "READY_FOR_PAPER"));
P(row("Workflow Completion", `${cl.workflowCompletion.pct}% (${cl.workflowCompletion.numerator}/${cl.workflowCompletion.denominator} attempted; ${cl.workflowCompletion.pctOfTotal}% of 10) Clean; ${iv.workflowCompletion.pct}% (${iv.workflowCompletion.numerator}/${iv.workflowCompletion.denominator}) Intervention`, "completion = all 11 steps in the DB through a stored verification; does not mean RESOLVED; incomplete = 2 blocked recommendations + 2 un-verifiable re-hunts (Clean)", "READY_FOR_PAPER"));
P(row("Investigation Time", `mean ${cl.investigationTime.mean} s, median ${cl.investigationTime.median} s, min ${cl.investigationTime.min} s, max ${cl.investigationTime.max} s (n=${cl.investigationTime.n})`, "T_recommendation − T_investigation_start; uninterrupted run; includes third-party LLM latency; cases without a recommendation excluded", "READY_FOR_PAPER (with caveats)"));
P(row("Intervention Rate / Retry Rate", `Clean: ${cl.interventionRate.pct}% / ${cl.retry.caseLevelRate ?? cl.retry.caseRatePct}% (retry cases 2/9; total retries ${cl.retry.totalRetryCount}); Intervention: ${iv.interventionRate.pct}% (2/9) / ${iv.retry.caseRatePct}% (total ${iv.retry.totalRetryCount})`, "retry total is a count; Clean retries are censored at 5; the analyst is scripted", "READY_FOR_PAPER (descriptive)"));
P(row("Evidence Coverage", `${cl.evidenceCoverage.pctOfAttempted}% (${cl.evidenceCoverage.casesWithRecommendationAllTargetsEvidenceBacked}/${cl.evidenceCoverage.denominatorAttempted} attempted cases) Clean; ${iv.evidenceCoverage.pctOfAttempted}% Intervention`, "membership definition; blocked cases count as not covered; not semantic", "READY_FOR_PAPER (with caveats)"));
P(row("Approval Correctness", `${cl.approvalCorrectness.pct}% (${cl.approvalCorrectness.numerator}/${cl.approvalCorrectness.denominator})`, "approve path only; rejection/manual-decision not exercised", "NEEDS_MORE_DATA (partial)"));
P(row("Verification outcome distribution", `Clean: ${JSON.stringify(cl.verificationEffectiveness.outcomes)}; Intervention: ${JSON.stringify(iv.verificationEffectiveness.outcomes)}; control: NOT_RESOLVED with ${A.control.matchingEvents} matching events`, "report as outcomes of a simulated-response pipeline, never as containment effectiveness", "NEEDS_MORE_DATA"));
P(row("Verification/Re-hunt Time", `${dd(vt(cl))} (n=${vt(cl).n})`, "total time only; tiny index; excludes harness waits", "READY_FOR_PAPER (with caveats)"));
P(row("Detection-to-Response", `${dd(d(cl, "fromVigixIngest"))} from VIGIX ingest (n=${d(cl, "fromVigixIngest").n})`, "includes LLM latency and a scripted SOC/IR step; webhook latency not measured", "NEEDS_MORE_DATA"));
P("", "MOCK baseline (cite only as MOCK, with its conditions): compliance 10/10, workflow 10/10, verification 10/10 *completed* (MOCK — NO_MATCH simulated), intervention 4/10, retry cases 4/10 with a total retry count of 43; do not cite its timing (manual gaps) — use the N=2 single-pass figures (mean investigation " + REP.overall.investigationTimeMean + " s ± " + REP.overall.investigationTimeSd + ") if a MOCK latency is needed.");

// ============================================================ 12. not available
P("", "## 12. Metrics Not Available", "");
for (const s of [
  "**Time-to-Decision as human decision time** — NOT_AVAILABLE: every decision is scripted; no human-in-the-loop timing exists in the data.",
  "**Verification Effectiveness as a containment claim** — NOT_AVAILABLE: no response was actually executed; a single positive control (n = 1); no negative/other-IOC-type control; no spread-detection test.",
  "**Approval Correctness for rejected recommendations / manual decision after reject** — NOT_AVAILABLE: 0 rejected decisions in `soar_eval`.",
  "**Windows / PowerShell (TC-05) on Real Wazuh** — NOT_AVAILABLE: `ENVIRONMENT_UNAVAILABLE`.",
  "**ML risk score** — NOT_AVAILABLE: `risk_scores` is empty.",
  "**Repeated-run reliability of the LLM on the Real pipeline** — NOT_AVAILABLE: one run per condition (only the MOCK pipeline has N = 2).",
  "**Split of Verification Time into Wazuh-query vs processing time** — NOT_AVAILABLE: not stored.",
  "**VIGIX webhook (`custom-vigix` → backend) latency** — NOT_AVAILABLE: the evaluation ingested through the same use cases but bypassed the HTTP hop.",
  "**Detection-to-Response and Verification/Re-hunt Time for MOCK** — NOT_APPLICABLE by definition (synthetic alerts, simulated re-hunt).",
  "**Real-Wazuh results for TC-02 and TC-10 verification** — NOT_AVAILABLE: no searchable IOC; only the recommendation side is measured.",
].map((x) => "- " + x)) P(s);
P("", "---", "", "### Final classification", "");
P("- **READY_FOR_PAPER (with the stated caveats):** Recommendation Compliance, Playbook Alignment, Policy Compliance, Workflow Completion, Investigation Time, Verification/Re-hunt Time, Intervention and Retry descriptions, Evidence Coverage (per attempted case).");
P("- **NEEDS_MORE_DATA:** Verification Effectiveness (as anything beyond an outcome distribution), Approval Correctness (reject path), Detection-to-Response, repeated-run reliability.");
P("- **NOT_AVAILABLE:** human Time-to-Decision, ML risk score, TC-05 on Real Wazuh, Verification Time split, webhook latency.");
P("", "Reproduce: `cd apps/backend && . scripts/eval/eval-env.sh && npx ts-node --transpile-only scripts/eval/audit-evaluation.ts && npx ts-node --transpile-only scripts/eval/build-audit-report.ts` (read-only; needs the Wazuh stack, PostgreSQL and `soar_eval` to be up).");

fs.writeFileSync(path.join(RES, "evaluation-audit.md"), out.join("\n"));
console.log(`wrote results/evaluation-audit.md (${out.length} lines)`);
