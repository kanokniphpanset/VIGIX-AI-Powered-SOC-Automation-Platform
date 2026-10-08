/**
 * build-2e-report.ts - Phase 2E report: a real-Wazuh evaluation run compared with the frozen baselines, with REAL_TELEMETRY
 * and HARNESS_GENERATED cases kept apart. READ-ONLY: it reads results/runs/<label>/run.json and the evaluation database
 * (DATABASE_URL, name must end with _eval) and writes only PHASE-2E-REPORT.md / phase-2e-comparison.json into the new run's folder.
 *
 *   cd apps/backend && DATABASE_URL=.../soar_p2e_eval \
 *   npx ts-node --transpile-only scripts/eval/p2e/build-2e-report.ts --run clean-p2e-real-wazuh-20261008 \
 *        [--baseline final-main-real-wazuh-20261001] [--baseline2 clean-v2-real-wazuh-20260930]
 *
 * Nothing here re-scores or re-interprets the baselines: their numbers are copied from their frozen run.json files.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { extractWazuhEvidenceV2 } from "../../../src/domain/investigation/evidenceV2/extractWazuhEvidenceV2";

const arg = (n: string, d?: string) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const ROOT = path.resolve(__dirname, "..", "..", "..", "..", "..");
const RUN = arg("run");
const BASELINES = [arg("baseline", "final-main-real-wazuh-20261001")!, arg("baseline2", "clean-v2-real-wazuh-20260930")!];
if (!RUN) { console.error("--run <label> is required"); process.exit(2); }
const dbName = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);
if (!/_eval$/.test(dbName)) { console.error(`refusing: DATABASE_URL database '${dbName}' must end with _eval`); process.exit(2); }

const readRun = (label: string) => JSON.parse(fs.readFileSync(path.join(ROOT, "results", "runs", label, "run.json"), "utf8"));
const byCase = (run: any): Record<string, any> => Object.fromEntries((run.cases ?? []).map((c: any) => [c.caseId, c]));
const ioc = (v: any) => (v ? `${v.found}/${v.expected}` : "n/a");
const verdict = (c: any) => (c ? `${c.verificationResult ?? "-"} (${c.verificationMode ?? "-"}, round ${c.rehuntRound ?? "-"})` : "not run");
const compliance = (c: any) => (c ? c.recommendationCompliance ?? "-" : "not run");

(async () => {
  const prisma = new PrismaClient();
  const run = readRun(RUN);
  const baselines = BASELINES.map((label) => { try { return { label, run: readRun(label) }; } catch { return null; } }).filter((b): b is { label: string; run: any } => !!b);
  const rows: any[] = [];

  for (const c of run.cases as any[]) {
    const alert = c.alertId ? await prisma.alert.findUnique({ where: { id: c.alertId } }) : null;
    const v2 = alert ? extractWazuhEvidenceV2(alert.rawPayload, { alertRowId: alert.id, receivedAt: alert.createdAt, externalAlertId: alert.externalAlertId }) : null;
    const prov = v2 && v2.isSuccess ? v2.value.provenance : null;
    const observations = c.incidentId
      ? (await prisma.iocObservation.findMany({ where: { ioc: { incidentId: c.incidentId } }, include: { ioc: true } })).map((o) => ({ type: o.ioc.iocType, value: o.ioc.iocValue, sourcePath: o.sourcePath, role: o.role, provenanceClass: o.provenanceClass, lastKnown: o.lastKnown }))
      : [];
    const verification = c.verificationId ? await prisma.verification.findUnique({ where: { id: c.verificationId } }) : null;
    const after = (verification?.afterState ?? null) as Record<string, any> | null;

    // Role of every IP the recommendation asked to block: the Phase 2C observation says whether it was the reporting host.
    const targets: { action: string; target: string; observedRoles: string[] }[] = [];
    for (const t of (c.actionMatch?.actualTargets ?? []) as string[]) {
      targets.push({ action: "(target)", target: t, observedRoles: [...new Set(observations.filter((o) => o.value === t).map((o) => o.role))] });
    }
    const selfTargets = targets.filter((t) => t.observedRoles.length > 0 && t.observedRoles.every((r) => r === "ENDPOINT_SELF"));

    const base = baselines.map((b) => ({ label: b.label, c: byCase(b.run)[c.caseId] }));
    rows.push({
      caseId: c.caseId, attackName: c.attackName, telemetry: c.telemetry,
      provenance: prov ? { class: prov.class, basis: prov.classBasis } : null,
      alert: { ruleId: c.wazuh?.ruleId ?? null, level: c.wazuh?.level ?? null, agent: c.wazuh?.agent ?? null, indexerDocId: c.wazuh?.indexerDocId ?? null },
      completeness: prov?.completeness ?? null,
      new: { compliance: c.recommendationCompliance, failedChecks: c.compliance?.failedChecks ?? [], iocRecall: c.iocRecall, actionMatch: c.actionMatch, verificationResult: c.verificationResult, verificationMode: c.verificationMode, rehuntError: c.rehuntError ?? null, correctRecommendation: c.correctRecommendation ?? null },
      verification: verification ? { result: verification.result, matchingEvents: verification.matchingEvents, spreadDetected: verification.spreadDetected, iocRecurrence: verification.iocRecurrence, threatContained: verification.threatContained, classification: after?.classification ?? null, totalMatched: after?.totalMatched ?? null, ignoredEvents: after?.ignoredEvents ?? null, correlationReasons: after?.correlationReasons ?? null, coverageComplete: after?.coverage?.complete ?? null, coverageGaps: after?.coverage?.gaps ?? null } : null,
      observations,
      selfTargets,
      baselines: base.map((b) => ({ label: b.label, compliance: b.c?.recommendationCompliance ?? null, iocRecall: b.c?.iocRecall ?? null, verificationResult: b.c?.verificationResult ?? null, verificationMode: b.c?.verificationMode ?? null, actualTargets: b.c?.actionMatch?.actualTargets ?? null })),
    });
  }
  await prisma.$disconnect();

  const notRun = ["TC-01", "TC-02", "TC-03", "TC-04", "TC-05", "TC-06", "TC-07", "TC-08", "TC-09", "TC-10"].filter((id) => !rows.some((r) => r.caseId === id));
  const groups: Record<string, any[]> = {};
  for (const r of rows) (groups[r.provenance?.class ?? "UNKNOWN"] ??= []).push(r);
  const stat = (rs: any[]) => ({
    cases: rs.map((r) => r.caseId),
    compliant: rs.filter((r) => r.new.compliance === "COMPLIANT").length,
    iocFound: rs.reduce((a, r) => a + (r.new.iocRecall?.found ?? 0), 0),
    iocExpected: rs.reduce((a, r) => a + (r.new.iocRecall?.expected ?? 0), 0),
    resolved: rs.filter((r) => r.new.verificationResult === "RESOLVED").length,
  });
  const summary = Object.fromEntries(Object.entries(groups).map(([k, v]) => [k, stat(v)]));
  const classes: Record<string, number> = {};
  for (const r of rows) { const k = r.verification?.classification ?? "(not classified)"; classes[k] = (classes[k] ?? 0) + 1; }

  const out = { run: RUN, database: dbName, groundTruthSha256: run.groundTruthSha256, baselinesUsed: baselines.map((b) => b.label), notRun, summaryByProvenance: summary, rehuntClassifications: classes, cases: rows };
  const dir = path.join(ROOT, "results", "runs", RUN);
  fs.writeFileSync(path.join(dir, "phase-2e-comparison.json"), JSON.stringify(out, null, 2) + "\n");

  const md: string[] = [];
  md.push(`# Phase 2E report - ${RUN}`, "", `Database \`${dbName}\` · ground truth sha256 \`${run.groundTruthSha256}\` · baselines: ${baselines.map((b) => `\`${b.label}\``).join(", ") || "none found"}`, "");
  md.push("Provenance of each case's alert is derived from the stored alert (Evidence Contract v2 `classifyProvenance`): **REAL_TELEMETRY** = stock Wazuh rule on a real agent log; **HARNESS_GENERATED** = real Wazuh pipeline, log line written by the evaluation harness (rules 100300-100350). Numbers from the two groups must not be pooled into a claim about real telemetry.", "");
  if (notRun.length) md.push(`**Not run in this report:** ${notRun.join(", ")}.`, "");
  md.push("## Summary by provenance", "", "| Provenance | Cases | Compliant | IOC recall (found/expected) | RESOLVED |", "|---|---|---|---|---|");
  for (const [k, s] of Object.entries(summary)) md.push(`| ${k} | ${s.cases.join(", ")} | ${s.compliant}/${s.cases.length} | ${s.iocFound}/${s.iocExpected} | ${s.resolved}/${s.cases.length} |`);
  md.push("", "Re-hunt classification of the new run: " + (Object.entries(classes).map(([k, v]) => `${k} ${v}`).join(", ") || "-"), "");
  md.push("## Per case", "", `| Case | Telemetry label | Provenance | IOC recall new (baselines) | Compliance new (baselines) | Verification new | Re-hunt class | Verification baselines |`, "|---|---|---|---|---|---|---|---|");
  for (const r of rows) {
    md.push(`| ${r.caseId} ${r.attackName} | ${r.telemetry ?? "-"} | ${r.provenance?.class ?? "?"} | ${ioc(r.new.iocRecall)} (${r.baselines.map((b: any) => ioc(b.iocRecall)).join(" / ")}) | ${r.new.compliance} (${r.baselines.map((b: any) => b.compliance ?? "-").join(" / ")}) | ${r.new.verificationResult ?? "-"} (${r.new.verificationMode ?? "-"}) | ${r.verification?.classification ?? "-"} | ${r.baselines.map((b: any) => `${b.verificationResult ?? "-"}/${b.verificationMode ?? "-"}`).join(" ; ")} |`);
  }
  md.push("", "## IOC roles recorded (ioc_observations)", "", "| Case | IOC | path | role | provenance |", "|---|---|---|---|---|");
  for (const r of rows) for (const o of r.observations) md.push(`| ${r.caseId} | \`${o.type}\` \`${String(o.value).slice(0, 70)}\` | ${o.sourcePath} | ${o.role}${o.lastKnown ? " (last known)" : ""} | ${o.provenanceClass} |`);
  const self = rows.filter((r) => r.selfTargets.length);
  md.push("", "## Recommended targets that are the reporting host's own address", "", self.length ? self.map((r) => `- ${r.caseId}: ${r.selfTargets.map((t: any) => t.target).join(", ")} (observed role ENDPOINT_SELF)`).join("\n") : "None of the recommended targets is recorded as ENDPOINT_SELF.");
  md.push("", "## Re-hunt detail", "", "| Case | result | class | matching | total matched | ignored | spread | recurrence | contained | coverage complete | gaps |", "|---|---|---|---|---|---|---|---|---|---|---|");
  for (const r of rows) if (r.verification) { const v = r.verification; md.push(`| ${r.caseId} | ${v.result} | ${v.classification ?? "-"} | ${v.matchingEvents ?? "-"} | ${v.totalMatched ?? "-"} | ${v.ignoredEvents ?? "-"} | ${v.spreadDetected} | ${v.iocRecurrence} | ${v.threatContained} | ${v.coverageComplete ?? "-"} | ${(v.coverageGaps ?? []).join("; ") || "-"} |`); }
  fs.writeFileSync(path.join(dir, "PHASE-2E-REPORT.md"), md.join("\n") + "\n");
  console.log(`wrote ${path.join(dir, "PHASE-2E-REPORT.md")}`);
})().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
