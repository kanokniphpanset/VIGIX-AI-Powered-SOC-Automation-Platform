/**
 * build-extended.ts — turns the EXTENDED evaluation runs into the result JSON files. Database is the source of truth:
 * every number is read from `soar_ext_eval` (and from the run JSON only where the harness recorded a scripted check).
 *
 *   EVAL_DB=soar_ext_eval . scripts/eval/eval-env.sh && npx ts-node --transpile-only scripts/eval/extended/build-extended.ts \
 *     --lowfp ext-low-fp-20261001 --esc ext-esc-20261001-r2 --esc-failed ext-esc-20261001 --rag-off ext-rag-off-20261001 --rag-on ext-rag-on-20261001 [--windows ext-windows-<label>]
 *
 * Writes results/extended-evaluation/extended-*.json. Nothing is estimated; a metric that cannot be computed says
 * `NOT CALCULABLE — <reason>`.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { RAG_GROUND_TRUTH } from "./rag/ragGroundTruth";

const arg = (n: string) => { const i = process.argv.indexOf(`--${n}`); return i > -1 ? process.argv[i + 1] : undefined; };
const ROOT = path.resolve(__dirname, "..", "..", "..", "..", "..");
const OUT = path.join(ROOT, "results", "extended-evaluation");
const RUNS = path.join(OUT, "runs");
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, "utf8"));
const write = (name: string, v: unknown) => { fs.writeFileSync(path.join(OUT, name), JSON.stringify(v, null, 2)); console.log("wrote", name); };
const r2 = (x: number) => Math.round(x * 100) / 100;
const pct = (n: number, d: number) => (d ? r2((100 * n) / d) : null);
function stats(xs: (number | null | undefined)[]) {
  const v = xs.filter((x): x is number => typeof x === "number" && Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return { n: 0, mean: null, median: null, sd: null, min: null, max: null };
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  const med = v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2;
  const sd = v.length > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (v.length - 1)) : 0;
  return { n: v.length, mean: r2(mean), median: r2(med), sd: r2(sd), min: v[0], max: v[v.length - 1] };
}

(async () => {
  const dbName = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);
  if (dbName !== "soar_ext_eval") throw new Error(`refusing to run: connected to '${dbName}', expected soar_ext_eval`);
  const prisma = new PrismaClient();
  const q = async <T = any>(sql: string, ...p: unknown[]) => prisma.$queryRawUnsafe<T[]>(sql, ...p);
  const pin = readJson(path.join(OUT, "ground-truth.sha256"));
  const summary: Record<string, any> = { generatedAt: new Date().toISOString(), database: dbName, groundTruthPins: pin, parts: {} };

  // =========================================================== A. LOW + False Positive
  const lowfpLabel = arg("lowfp");
  if (lowfpLabel) {
    const run = readJson(path.join(RUNS, `${lowfpLabel}.json`));
    const res: any[] = run.results;
    // DB re-check: every alert by id; severity from the DB; any incident/analysis/ticket linked to LOW / FP-MEDIUM alerts
    const rows: any[] = [];
    for (const r of res) {
      const a = r.alertId ? (await q(`select a.severity, a.workflow_state, a.triage_disposition, a.closed_at, (select count(*) from incident_alerts ia where ia.alert_id::text = a.id::text) as linked, (a.raw_payload->'rule'->>'level')::int as level, a.raw_payload->'rule'->>'id' as rule from alerts a where a.id::text = $1`, r.alertId))[0] : null;
      const audits = r.alertId ? await q(`select action from audit_logs where entity_id::text = $1 order by created_at`, r.alertId) : [];
      const inc = r.incidentId ? (await q(`select status, priority from incidents where id::text = $1`, r.incidentId))[0] : null;
      const exec = r.incidentId ? Number((await q(`select count(*) c from step_executions se join response_plans rp on rp.id::text = se.plan_id::text where rp.incident_id::text = $1`, r.incidentId))[0].c) : 0;
      rows.push({
        case: r.caseId, kind: r.kind, title: r.title, benignReason: r.benignReason, rule: a?.rule, level: a?.level, severityDb: a?.severity, expectedSeverity: r.groundTruth.expected.severity,
        alertWorkflowState: a?.workflow_state, disposition: a?.triage_disposition, closed: !!a?.closed_at, incidentLinked: Number(a?.linked ?? 0) > 0, incidentStatus: inc?.status ?? null,
        auditActions: audits.map((x: any) => x.action), stepExecutions: exec, harnessChecks: `${r.checksPassed}/${r.checksTotal}`, result: r.result, dbDelta: r.dbDelta ?? null,
        aiSeconds: r.aiSeconds ?? null, modelAttempts: r.modelAttempts ?? null, recommendation: r.recommendation ?? null, aiMentionsBenignContext: r.aiMentionsBenignContext ?? null,
        failedChecks: r.checks.filter((c: any) => !c.pass), observations: r.observations,
      });
    }
    const low = rows.filter((x) => x.kind === "LOW"), fpm = rows.filter((x) => x.kind === "FP_MEDIUM"), fph = rows.filter((x) => x.kind === "FP_HIGH");
    const checks = res.flatMap((r) => r.checks.map((c: any) => ({ case: r.caseId, ...c })));
    const metrics = {
      lowKeptOutOfWorkflow: { n: low.filter((x) => x.severityDb === "low" && !x.incidentLinked && x.auditActions.includes("ALERT_OUTSIDE_SOC_WORKFLOW") && x.stepExecutions === 0 && Object.values(x.dbDelta ?? {}).every((v) => v === 0)).length, of: low.length },
      lowSeverityMatchesWazuhLevel: { n: low.filter((x) => x.severityDb === x.expectedSeverity).length, of: low.length, levels: low.map((x) => `${x.case}: level ${x.level} → ${x.severityDb}`) },
      mediumFalsePositivesClosedWithoutIncidentOrAi: { n: fpm.filter((x) => x.closed && x.disposition === "FALSE_POSITIVE" && !x.incidentLinked && Object.values(x.dbDelta ?? {}).every((v) => v === 0)).length, of: fpm.length },
      highCriticalAutoIncident: { n: fph.filter((x) => x.incidentLinked).length, of: fph.length },
      highCriticalNotClosableFromInbox: { n: fph.filter((x) => x.harnessChecks && res.find((r) => r.caseId === x.case).checks.find((c: any) => c.id === "H2")?.pass).length, of: fph.length },
      benignRecommendationsProducedForHighCritical: { n: fph.filter((x) => x.recommendation).length, of: fph.length, note: "cost of a false positive; the AI has no false-positive verdict and is not graded on one" },
      irRejectedBenignRecommendation: { n: fph.filter((x) => res.find((r) => r.caseId === x.case).checks.find((c: any) => c.id === "H4")?.pass).length, of: fph.length },
      benignAlertsLeadingToExecutedResponse: { n: rows.filter((x) => x.stepExecutions > 0).length, of: rows.length },
      harnessChecks: { passed: checks.filter((c: any) => c.pass).length, of: checks.length },
      overallFalsePositiveRate: "NOT CALCULABLE — a rule-level false-positive rate needs a labelled benign event stream (denominator = all benign events); only 3 benign scenarios were tested, so only handling of known-benign alerts is measured",
      aiFalsePositiveDetection: "NOT CALCULABLE — VIGIX emits no false-positive verdict (AI never triages); nothing to score",
      aiMentionsBenignContext: fph.map((x) => ({ case: x.case, keywordObservation: x.aiMentionsBenignContext })),
    };
    write("extended-low-fp.json", { part: "A", title: "LOW severity and False Positive handling", run: lowfpLabel, startedAt: run.startedAt, finishedAt: run.finishedAt, groundTruthSha256: run.groundTruthSha256, verificationMode: "n/a (no response executed)", cases: rows, metrics, allChecks: checks });
    summary.parts.lowFp = metrics;
  }

  // =========================================================== C. ESCALATED
  const escLabel = arg("esc");
  if (escLabel) {
    const run = readJson(path.join(RUNS, `${escLabel}.json`));
    const failed = arg("esc-failed") ? readJson(path.join(RUNS, `${arg("esc-failed")}.json`)) : null;
    const iid = run.incidentId;
    const vers = await q(`select v.result, v.matching_events, v.ioc_recurrence, v.threat_contained, v.after_state->>'evidenceSource' as src, v.verified_at from verifications v where v.incident_id::text = $1 order by v.verified_at`, iid);
    const inc = (await q(`select status, investigation_number from incidents where id::text = $1`, iid))[0];
    const audits = await q(`select action, actor, metadata from audit_logs where metadata::text like $1 or entity_id::text = $2 order by created_at`, `%${iid}%`, iid);
    const cnt = (a: string) => audits.filter((x: any) => x.action === a).length;
    const recs = await q(`select recommendation_number, investigation_number, status from recommendations where incident_id::text = $1 order by recommendation_number`, iid);
    const plans = await q(`select rp.status, ac.code as action, rp.target from response_plans rp left join actions ac on ac.id::text = rp.action_id::text where rp.incident_id::text = $1 order by rp.created_at`, iid);
    const nonSystemActors = audits.filter((x: any) => ["INCIDENT_ESCALATED", "INVESTIGATION_ESCALATED", "INVESTIGATION_REOPENED"].includes(x.action)).map((x: any) => x.actor);
    const res = {
      part: "C", title: "ESCALATED path (3 re-hunt rounds)", run: escLabel, failedFirstAttempt: failed ? { run: failed.label, result: failed.result, fatal: failed.fatal, classification: "INFRASTRUCTURE — the LLM endpoint failed DNS resolution (ConnectError / getaddrinfo) during analysis/recommendation; recorded, not counted; the case was repeated after the endpoint recovered" } : null,
      incidentId: iid, verificationMode: "REAL_WAZUH",
      verifications: vers.map((v: any, i: number) => ({ round: i + 1, result: v.result, matchingEvents: Number(v.matching_events), iocRecurrence: v.ioc_recurrence, threatContained: v.threat_contained, evidenceSource: v.src })),
      incidentFinal: { status: inc?.status, investigationNumber: Number(inc?.investigation_number) },
      auditCounts: { INVESTIGATION_REOPENED: cnt("INVESTIGATION_REOPENED"), INVESTIGATION_ESCALATED: cnt("INVESTIGATION_ESCALATED"), INCIDENT_ESCALATED: cnt("INCIDENT_ESCALATED") },
      escalationReasons: audits.filter((x: any) => x.action === "INVESTIGATION_ESCALATED").map((x: any) => x.metadata?.reasons),
      recommendations: recs.map((r: any) => ({ number: Number(r.recommendation_number), investigation: Number(r.investigation_number), status: r.status })),
      responseTickets: plans, harnessRounds: run.rounds.map((r: any) => ({ round: r.round, investigation: r.investigationNumber, recommendation: r.recommendation, fallbackToEarlierRecommendation: r.fallbackToEarlierRecommendation, generation: r.recommendationGeneration, recurrenceAlertSeen: r.recurrence?.alertSeenInIndexer, verification: r.verification, incidentAfter: r.incidentAfter })),
      actorsOfEscalationAudits: nonSystemActors, harnessChecks: { passed: run.checks.filter((c: any) => c.pass).length, of: run.checks.length, list: run.checks },
      escalatedObserved: vers.length === 3 && vers.every((v: any) => v.result === "NOT_RESOLVED") && inc?.status === "escalated",
      outcome: vers.length === 3 && vers.every((v: any) => v.result === "NOT_RESOLVED") && inc?.status === "escalated" ? "ESCALATED (third round reached)" : "NOT ESCALATED",
      observations: run.observations,
      limitation: "The recurrence is produced by the harness repeating the beacon after each response; the NOT_RESOLVED / reopen / ESCALATED decisions are made by the product code from REAL_WAZUH re-hunt evidence. Only one scenario (TC-07 telemetry, controlled custom-rule events).",
    };
    write("extended-escalation.json", res);
    summary.parts.escalation = { outcome: res.outcome, rounds: res.verifications.length, auditCounts: res.auditCounts, incidentFinal: res.incidentFinal, harnessChecks: res.harnessChecks };
  }

  // =========================================================== B. RAG
  const offLabel = arg("rag-off"), onLabel = arg("rag-on");
  if (offLabel && onLabel) {
    const arms: Record<string, any> = {};
    for (const [arm, label] of [["A_empty_corpus", offLabel], ["B_runbook_corpus", onLabel]] as const) {
      const run = readJson(path.join(ROOT, "results", "runs", label, "run.json"));
      const per: any[] = [];
      for (const c of run.cases) {
        if (c.environmentStatus === "ENVIRONMENT_UNAVAILABLE") { per.push({ case: c.caseId, finalResult: "ENVIRONMENT_UNAVAILABLE" }); continue; }
        const rag = c.incidentId ? (await q(`select ar.output from agent_results ar join agent_executions ae on ae.id::text = ar.agent_execution_id::text where ae.incident_id::text = $1 and ar.agent_name = 'rag' order by ar.created_at desc limit 1`, c.incidentId))[0]?.output : null;
        const chunks: any[] = rag?.chunks ?? [];
        const gt = RAG_GROUND_TRUTH.find((g) => g.caseId === c.caseId);
        const ranked = chunks.map((x) => x.doc_id as string);
        const rel = new Set([...(gt?.primary ?? []), ...(gt?.relevant ?? [])]);
        const top = ranked.slice(0, 3);
        const hitsRel = top.filter((d) => rel.has(d)).length;
        const firstRel = ranked.findIndex((d) => rel.has(d));
        const firstPrimary = ranked.findIndex((d) => gt?.primary.includes(d));
        const ip = c.incidentId ? await q(`select ac.code, rs.target, a.raw_payload->'data'->>'srcip' srcip, a.raw_payload->'data'->>'dstip' dstip from recommendation_steps rs join recommendations r on r.id::text = rs.recommendation_id::text join actions ac on ac.id::text = rs.action_id::text join incident_alerts ia on ia.incident_id::text = r.incident_id::text join alerts a on a.id::text = ia.alert_id::text where r.incident_id::text = $1 and r.status = 'VALIDATED' and ac.code in ('ACT-BLOCK-SOURCE-IP','ACT-BLOCK-DESTINATION-IP')`, c.incidentId) : [];
        const ipSteps = ip.map((s: any) => ({ action: s.code, target: s.target, correctRole: s.target === (s.code === "ACT-BLOCK-SOURCE-IP" ? s.srcip : s.dstip) }));
        per.push({
          case: c.caseId, incidentId: c.incidentId, ragStatus: rag?.status ?? (chunks.length ? "found (no status field; chunks present)" : "NOT_RECORDED"), ragError: rag?.error ?? null, retrieved: ranked, scores: chunks.map((x) => r2(x.score)),
          primary: gt?.primary, relevant: gt?.relevant, retrieval: ranked.length ? { primaryHitAt1: gt?.primary.includes(ranked[0]) ?? false, primaryHitAt3: top.some((d) => gt?.primary.includes(d)), relevantHitAt3: hitsRel > 0, precisionAt3: r2(hitsRel / Math.max(1, top.length)), recallAt3: r2(hitsRel / Math.max(1, rel.size)), firstRelevantRank: firstRel >= 0 ? firstRel + 1 : null, firstPrimaryRank: firstPrimary >= 0 ? firstPrimary + 1 : null, reciprocalRank: firstRel >= 0 ? r2(1 / (firstRel + 1)) : 0 } : null,
          compliance: c.recommendationCompliance, playbook: c.playbookCode, retries: c.invalidOutputCount, workflowCompleted: c.workflowCompleted, verification: c.verificationResult, verificationMode: c.verificationMode,
          investigationSeconds: c.investigationTimeSeconds, interventions: (c.interventions ?? []).length, ipSteps, observations: (c.observations ?? []).filter((o: string) => /INFRA|NO_VALID|MISSING/.test(o)).map((o: string) => o.slice(0, 160)),
          finalResult: c.recommendationCompliance === "NOT_EVALUATED" ? ((c.observations ?? []).some((o: string) => /INFRASTRUCTURE_FAILURE/.test(o)) ? "INCOMPLETE" : "FAIL") : c.workflowCompleted ? "PASS" : "INCOMPLETE",
        });
      }
      const ev = per.filter((x) => x.finalResult !== "ENVIRONMENT_UNAVAILABLE");
      const ret = per.filter((x) => x.retrieval);
      arms[arm] = {
        run: label, startedAt: run.startedAt, finishedAt: run.finishedAt, groundTruthSha256: run.groundTruthSha256, cases: per,
        compliance: { compliant: ev.filter((x) => x.compliance === "COMPLIANT").length, evaluated: ev.filter((x) => x.compliance && x.compliance !== "NOT_EVALUATED").length, attempted: ev.length },
        noValidRecommendation: ev.filter((x) => x.compliance === "NOT_EVALUATED").map((x) => x.case),
        retries: { cases: ev.filter((x) => (x.retries ?? 0) > 0).length, total: ev.reduce((s, x) => s + (x.retries ?? 0), 0), of: ev.length },
        workflowCompleted: { n: ev.filter((x) => x.workflowCompleted).length, of: ev.length },
        investigationSeconds: stats(ev.map((x) => x.investigationSeconds)),
        ragStatuses: per.reduce((m: any, x) => { if (x.ragStatus) m[x.ragStatus] = (m[x.ragStatus] ?? 0) + 1; return m; }, {}),
        retrieval: ret.length ? { casesWithRetrieval: ret.length, primaryHitAt1: { n: ret.filter((x) => x.retrieval.primaryHitAt1).length, of: ret.length }, primaryHitAt3: { n: ret.filter((x) => x.retrieval.primaryHitAt3).length, of: ret.length }, relevantHitAt3: { n: ret.filter((x) => x.retrieval.relevantHitAt3).length, of: ret.length }, precisionAt3: stats(ret.map((x) => x.retrieval.precisionAt3)), recallAt3: stats(ret.map((x) => x.retrieval.recallAt3)), mrr: stats(ret.map((x) => x.retrieval.reciprocalRank)) } : "NOT CALCULABLE — no document was retrieved (empty corpus)",
        ipRole: (() => { const s = per.flatMap((x) => x.ipSteps ?? []); const d = s.filter((x: any) => x.action === "ACT-BLOCK-DESTINATION-IP"); return { allIpSteps: { correct: s.filter((x: any) => x.correctRole).length, of: s.length }, destinationIpSteps: { correct: d.filter((x: any) => x.correctRole).length, of: d.length } }; })(),
      };
    }
    const searchLog = fs.existsSync(path.join(OUT, "logs", "rag-search-requests.jsonl")) ? fs.readFileSync(path.join(OUT, "logs", "rag-search-requests.jsonl"), "utf8").trim().split("\n").length : 0;
    const A = arms.A_empty_corpus, B = arms.B_runbook_corpus;
    const paired = A.cases.map((a: any) => { const b = B.cases.find((x: any) => x.case === a.case); return { case: a.case, A: { compliance: a.compliance, retries: a.retries, workflow: a.workflowCompleted, playbook: a.playbook }, B: b ? { compliance: b.compliance, retries: b.retries, workflow: b.workflowCompleted, playbook: b.playbook } : null, complianceChanged: b ? a.compliance !== b.compliance : null }; });
    const res = {
      part: "B", title: "RAG evaluation (runbook corpus)", design: "same 10 cases, same pipeline (clean mode, no analyst correction), two conditions: A = RAG reachable but the isolated Qdrant is EMPTY (retrieval status not_found); B = the 17 ACTIVE runbooks indexed by the project's own indexer. One run per case per arm: differences are NOT attributable to RAG beyond LLM run-to-run variation.",
      corpus: { runbooks: 17, indexer: "apps/backend/scripts/indexRunbooksToQdrant.ts", embeddingModel: "BAAI/bge-small-en-v1.5 (384-d, cosine)", qdrant: "isolated container vigix-eval-qdrant (1.19.1) on :6335", knowledgeTypeDocuments: 0, note: "all runbooks carry sourceType PLAYBOOK; the KNOWLEDGE side of the dual retrieval has no documents by construction" },
      groundTruthSha256: pin.rag, arms, paired, searchRequestsLogged: searchLog,
      limitations: ["Relevance labels are the author's (frozen before retrieval) and the corpus has only 17 short runbooks; Hit@3 on 17 documents is easy.", "n = 9 cases; one run per arm; no statistical test is reported.", "The recommendation prompt also receives runbook text (PLAYBOOK top-3) — the effect on the recommendation cannot be separated from LLM variance.", "TC-05 ENVIRONMENT_UNAVAILABLE in this part."],
    };
    write("extended-rag.json", res);
    summary.parts.rag = { A: { compliance: A.compliance, retries: A.retries, workflow: A.workflowCompleted, ipRole: A.ipRole, ragStatuses: A.ragStatuses }, B: { compliance: B.compliance, retries: B.retries, workflow: B.workflowCompleted, ipRole: B.ipRole, retrieval: B.retrieval, ragStatuses: B.ragStatuses } };
  }

  // =========================================================== D. Windows
  const winLabel = arg("windows");
  if (winLabel) {
    const run = readJson(path.join(RUNS, `${winLabel}.json`));
    write("extended-windows.json", { part: "D", title: "Windows endpoint (TC-05 PowerShell)", ...run });
    summary.parts.windows = { result: run.result, run: winLabel };
  } else {
    write("extended-windows.json", { part: "D", title: "Windows endpoint (TC-05 PowerShell)", result: "ENVIRONMENT_UNAVAILABLE", reason: "No Windows endpoint with a Wazuh agent has been connected; nothing was simulated or fabricated." });
    summary.parts.windows = { result: "ENVIRONMENT_UNAVAILABLE" };
  }
  write("extended-kpi-summary.json", summary);
  await prisma.$disconnect();
})().catch((e) => { console.error(e); process.exit(1); });
