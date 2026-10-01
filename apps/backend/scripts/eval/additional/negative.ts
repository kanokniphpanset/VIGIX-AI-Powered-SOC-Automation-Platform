/**
 * negative.ts — Evaluation C: negative / reject-path validation (Evidence -> Recommendation -> Validation -> Policy ->
 * Human decision). It does NOT test attack detection and says nothing about AI accuracy.
 *
 * Part 1 — invalid recommendations vs the REAL deterministic validator (`RecommendationValidator`, the same instance
 * of logic production uses, with the real Action/Runbook catalogs and the Policy results embedded in the context):
 *   for each scenario a well-formed candidate is built for a real incident context of the frozen Clean/Intervention
 *   Run. A POSITIVE CONTROL first proves the unmodified candidate validates; then ONE fault is injected and the
 *   result is recorded. Nothing is persisted.
 *
 * Part 2 — governance gates with the real use cases on the cloned DB (`soar_addl_eval`): IR reject, wrong-role /
 *   AI / admin decisions, start before approval, re-hunt before completion, manual decision after reject, and the
 *   rule that an incident can never be RESOLVED manually.
 *
 *   cd apps/backend && EVAL_DB=soar_addl_eval . scripts/eval/eval-env.sh
 *   npx ts-node --transpile-only scripts/eval/additional/negative.ts
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { iocKind } from "../../../src/domain/knowledge/knowledgeTypes";
import { PrismaResponsePlanRepository } from "../../../src/infrastructure/database/postgres/repositories/ResponsePlanRepository.prisma";
import { ManualDecisionUseCase } from "../../../src/application/approval/use-cases/ManualDecision.usecase";
import { UpdateIncidentStatusUseCase } from "../../../src/application/incident/use-cases/UpdateIncidentStatus.usecase";
import { buildEvalContext, IR } from "../wiring";
import { TENANT, DATA, CLEAN_LABEL, INTERVENTION_LABEL, frozenRun, buildPipeline, preflightAdditional } from "./common";

const POLICY_CODES = ["WRONG_RESPONSIBLE_ROLE", "POLICY_BYPASS", "POLICY_UNAVAILABLE"];
const codesOf = (violations: string[]) => [...new Set(violations.map((v) => String(v).split(":")[0]))];
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

function baseCandidate(ctx: any, actionCode: string, target: string) {
  const proc = ctx.actionProcedures.find((p: any) => p.actionCode === actionCode);
  if (!proc) throw new Error(`action ${actionCode} is not offered by the playbook of this context`);
  const evRef = ctx.evidence.find((e: any) => e.ref)?.ref, iRef = ctx.iocs.find((i: any) => i.iocValue === target)?.ref;
  return {
    summary: `Apply ${proc.actionName} to ${target}, recorded in the alert evidence.`,
    steps: [{
      stepOrder: 1, action: actionCode, objective: `Handle the indicator ${target}.`, responsibleRole: proc.policy.responsibleRole, target,
      reason: `${target} is recorded in this incident's evidence.`, evidenceRefs: [evRef, iRef].filter(Boolean),
      instructions: [{ order: 1, instruction: `Apply the ${proc.actionName} runbook to ${target}.`, target }, { order: 2, instruction: `Record the result of applying the runbook for ${target}.` }],
      playbook: ctx.playbook.code, runbook: proc.runbookCode, verificationCriteria: proc.verificationCriteria?.[0] ?? `The indicator ${target} is handled as the runbook describes.`,
      expectedResult: null, missingEvidence: [], confidence: 0.8,
    }],
  };
}

(async () => {
  const prisma = new PrismaClient();
  const pre = await preflightAdditional();
  const clean = frozenRun(CLEAN_LABEL), interv = frozenRun(INTERVENTION_LABEL);
  const P = buildPipeline(prisma, process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8001", { firstRound: true });
  const startedAt = new Date().toISOString();

  // ------------------------------------------------------------------ Part 1: validator / policy scenarios
  const sqlInc = clean.cases.find((c: any) => c.caseId === "TC-06").incidentId as string;
  const procInc = interv.cases.find((c: any) => c.caseId === "TC-08").incidentId as string;
  const sql = (await P.builder.build(sqlInc, TENANT)).value as any;
  const proc = (await P.builder.build(procInc, TENANT)).value as any;
  const attacker = (sql.iocs.find((i: any) => iocKind(i.iocType) === "ip" && i.manual !== undefined && sql.evidence.some((e: any) => e.iocValues.includes(i.iocValue))) ?? sql.iocs.find((i: any) => iocKind(i.iocType) === "ip")).iocValue as string;
  const host = sql.affectedHosts[0] as string;
  const procTarget = proc.iocs.find((i: any) => iocKind(i.iocType) === "process")?.iocValue as string;
  const sqlPolicy = sql.actionProcedures.find((p: any) => p.actionCode === "ACT-BLOCK-SOURCE-IP").policy;

  type Scn = { id: string; name: string; invalid_condition: string; layer: "VALIDATOR" | "POLICY"; expect: string; ctxName: string; ctx: any; base: any; mutate: (cand: any, ctx: any) => { cand: any; ctx: any } };
  const withStep = (cand: any, patch: any) => { const c = clone(cand); Object.assign(c.steps[0], patch); return c; };
  const sqlBase = baseCandidate(sql, "ACT-BLOCK-SOURCE-IP", attacker);
  const procBase = baseCandidate(proc, "ACT-KILL-PROCESS", procTarget);
  const otherRole = sqlPolicy.responsibleRole === "IR_TEAM" ? "SOC" : "IR_TEAM";
  const scenarios: Scn[] = [
    { id: "NEG-01", name: "Unsupported target (IOC not in the evidence)", invalid_condition: "the recommended target is an IP address that does not exist in the incident's evidence", layer: "VALIDATOR", expect: "INVENTED_TARGET", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { target: "198.51.100.77", instructions: [{ order: 1, instruction: "Apply the runbook to 198.51.100.77.", target: "198.51.100.77" }] }), ctx: x }) },
    { id: "NEG-02", name: "Required evidence type absent", invalid_condition: "ACT-KILL-PROCESS on a recorded process while the COMMAND_LINE evidence it requires is absent from the incident", layer: "POLICY", expect: "INSUFFICIENT_EVIDENCE", ctxName: "TC-08 intervention incident (command evidence removed from the context)", ctx: proc, base: procBase, mutate: (c, x) => ({ cand: c, ctx: { ...x, iocs: x.iocs.filter((i: any) => iocKind(i.iocType) !== "command") } }) },
    { id: "NEG-03", name: "Policy: wrong responsible role", invalid_condition: `responsibleRole "${otherRole}" while Policy assigns "${sqlPolicy.responsibleRole}" to this action`, layer: "POLICY", expect: "WRONG_RESPONSIBLE_ROLE", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { responsibleRole: otherRole }), ctx: x }) },
    { id: "NEG-04", name: "Policy: approval waived", invalid_condition: `candidate marks approval as not required and says to execute without approval while Policy requires ${sqlPolicy.approvalRole ?? "an"} approval`, layer: "POLICY", expect: "POLICY_BYPASS", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { requiresApprovalSuggested: false, instructions: [{ order: 1, instruction: `Apply the runbook to ${attacker} without approval.`, target: attacker }] }), ctx: x }) },
    { id: "NEG-05", name: "Action outside the selected playbook", invalid_condition: "ACT-ISOLATE-ENDPOINT is not allowed by the SQL-injection playbook", layer: "VALIDATOR", expect: "ACTION_NOT_IN_PLAYBOOK", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { action: "ACT-ISOLATE-ENDPOINT", target: host, runbook: "RB-UNKNOWN", instructions: [{ order: 1, instruction: `Apply the runbook to ${host}.`, target: host }] }), ctx: x }) },
    { id: "NEG-06", name: "Action that does not exist in the Action Catalog", invalid_condition: "the recommended action code ACT-WIPE-DISK is not in the catalog", layer: "VALIDATOR", expect: "INVENTED_ACTION", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { action: "ACT-WIPE-DISK" }), ctx: x }) },
    { id: "NEG-07", name: "Target of the wrong type for the action", invalid_condition: `ACT-BLOCK-SOURCE-IP (operates on an IP) aimed at the host "${host}"`, layer: "VALIDATOR", expect: "TARGET_TYPE_MISMATCH", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { target: host, instructions: [{ order: 1, instruction: `Apply the runbook to ${host}.`, target: host }] }), ctx: x }) },
    { id: "NEG-08", name: "Playbook different from the backend-selected one", invalid_condition: `step names playbook PB-MALWARE while the backend selected ${sql.playbook.code}`, layer: "VALIDATOR", expect: "PLAYBOOK_MISMATCH", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { playbook: "PB-MALWARE" }), ctx: x }) },
    { id: "NEG-09", name: "Fabricated evidence reference", invalid_condition: 'evidenceRefs cites "E99", an evidence id that does not exist in this investigation', layer: "VALIDATOR", expect: "INVENTED_EVIDENCE", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { evidenceRefs: ["E99"] }), ctx: x }) },
    { id: "NEG-10", name: "Invented indicator in free text", invalid_condition: "the reason cites the IP 203.0.113.250, which is not in the incident evidence", layer: "VALIDATOR", expect: "INVENTED_IOC", ctxName: "TC-06 clean incident", ctx: sql, base: sqlBase, mutate: (c, x) => ({ cand: withStep(c, { reason: `Traffic from 203.0.113.250 was also seen.` }), ctx: x }) },
  ];

  const results: any[] = [];
  for (const s of scenarios) {
    const control = await P.validator.validate(s.base, s.ctx, TENANT);
    const m = s.mutate(s.base, s.ctx);
    const out = await P.validator.validate(m.cand, m.ctx, TENANT);
    const codes = codesOf(out.violations);
    const rejected = out.status !== "VALIDATED";
    results.push({
      case_id: s.id, scenario: s.name, invalid_condition: s.invalid_condition, context: s.ctxName, expected_layer: s.layer, expected_result: `${s.layer} REJECT (${s.expect})`,
      positive_control: control.status === "VALIDATED" ? "VALIDATED (unmodified candidate accepted)" : `CONTROL FAILED: ${control.violations.slice(0, 2).join(" | ")}`, control_valid: control.status === "VALIDATED",
      actual_result: rejected ? "REJECTED" : "ACCEPTED", validator_result: rejected ? `INVALID: ${codes.join(", ")}` : "VALIDATED",
      policy_result: rejected ? (codes.filter((c) => POLICY_CODES.includes(c) || (c === "INSUFFICIENT_EVIDENCE" && out.violations.some((v) => /POL-A0\d/.test(v)))).length ? `POLICY-DERIVED: ${codes.filter((c) => POLICY_CODES.includes(c) || c === "INSUFFICIENT_EVIDENCE").join(", ")}${out.violations.filter((v) => /POL-A0\d/.test(v)).length ? " (" + [...new Set(out.violations.join(" ").match(/POL-A0\d/g) ?? [])].join(",") + ")" : ""}` : "no Policy-derived violation (rejected by validator knowledge/grounding rules)") : "not reached",
      violation_codes: codes, violation_messages: out.violations.map((v) => v.slice(0, 220)), expected_code_present: codes.includes(s.expect),
      final_status: rejected ? "REJECTED — nothing persisted, no response ticket can be created" : "ACCEPTED (invalid recommendation was not rejected)",
    });
    console.log(`${s.id}: control=${control.status} → ${rejected ? "REJECTED" : "ACCEPTED"} [${codes.join(",")}] expected ${s.expect}: ${codes.includes(s.expect) ? "yes" : "NO"}`);
  }
  const valid = results.filter((r) => r.control_valid);
  const rejectedN = valid.filter((r) => r.actual_result === "REJECTED").length;
  const rejectedExpected = valid.filter((r) => r.actual_result === "REJECTED" && r.expected_code_present).length;

  // ------------------------------------------------------------------ Part 2: governance gates (real use cases, cloned DB)
  const E = buildEvalContext(prisma, process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8001");
  const plans = new PrismaResponsePlanRepository(prisma);
  const manual = new ManualDecisionUseCase(E.approvals as any, plans as any, P.audit);
  const setStatus = new UpdateIncidentStatusUseCase(P.incidents as any, P.audit);
  const gates: any[] = [];
  const gate = (id: string, scenario: string, expected: string, actual: string, pass: boolean, extra: Record<string, unknown> = {}) => { gates.push({ id, scenario, expected, actual, pass, ...extra }); console.log(`${id} ${pass ? "PASS" : "FAIL"} — ${scenario}: expected ${expected}, actual ${actual}`); };
  const err = (r: any) => (r.isFailure ? String(r.error) : `OK(${r.value?.status ?? ""})`);

  const gInc = clean.cases.find((c: any) => c.caseId === "TC-10").incidentId as string;
  const rec = await prisma.recommendation.findFirst({ where: { incidentId: gInc, status: "VALIDATED" }, orderBy: { recommendationNumber: "desc" }, include: { steps: { include: { action: true }, orderBy: { stepOrder: "asc" } } } });
  const step2 = rec?.steps.find((s) => s.actionId && s.stepOrder === 2) ?? rec?.steps.filter((s) => s.actionId)[1];
  const incBefore = await prisma.incident.findUnique({ where: { id: gInc } });
  if (!rec || !step2) { gate("G0", "prepare a second response ticket for the same recommendation", "a validated recommendation with ≥ 2 steps", "not available", false); }
  else {
    const created = await E.createPlan.execute({ recommendationId: rec.id, stepId: step2.id, tenantId: TENANT });
    gate("G0", "SOC sends step 2 of a validated recommendation to IR", "ticket PENDING_IR_DECISION (needs IR decision)", err(created), created.isSuccess && created.value.status === "PENDING_IR_DECISION", { action: step2.action?.code, target: step2.target });
    if (created.isSuccess) {
      const planId = created.value.id;
      const pending = async () => (await E.approvals.findByResponse(planId, TENANT)).find((a: any) => a.status === "pending");
      const planNow = async () => (await plans.findById(planId, TENANT))!;
      const stepExec = async () => prisma.stepExecution.count({ where: { planId } });
      const s1 = await E.start.execute({ responseId: planId, tenantId: TENANT, startedBy: IR });
      gate("G1", "start the response before any IR decision", "blocked (APPROVAL_PENDING)", err(s1), s1.isFailure && String(s1.error) === "APPROVAL_PENDING");
      const rh1 = await E.rehunt.execute({ incidentId: gInc, responseId: planId, tenantId: TENANT, verifiedBy: IR });
      gate("G2", "re-hunt/verification requested before the response is completed", "blocked (RESPONSE_NOT_COMPLETED)", err(rh1), rh1.isFailure && String(rh1.error) === "RESPONSE_NOT_COMPLETED");
      const a0 = await pending();
      for (const [id, role, exp] of [["G3", "SOC", "ROLE_MISMATCH"], ["G4", "AI_AGENT", "ROLE_MISMATCH"], ["G5", "admin", "ADMIN_NOT_APPROVER"]] as const) {
        const d = await E.decide.execute({ approvalId: a0!.id, tenantId: TENANT, status: "approved", decidedBy: role, decidedByRole: role, comment: "attempt" });
        gate(id, `approval attempted by role "${role}" (approval belongs to IR_TEAM)`, `denied (${exp})`, err(d), d.isFailure && String(d.error) === exp);
      }
      const dn = await E.decide.execute({ approvalId: a0!.id, tenantId: TENANT, status: "approved", decidedBy: IR, decidedByRole: "IR_TEAM", comment: null });
      gate("G6", "IR_TEAM decision without a note", "denied (NOTE_REQUIRED)", err(dn), dn.isFailure && String(dn.error) === "NOTE_REQUIRED");
      gate("G7", "denied attempts left the ticket untouched", "PENDING_IR_DECISION, approval pending", `${(await planNow()).status}, approval ${(await pending())?.status ?? "none"}`, (await planNow()).status === "PENDING_IR_DECISION" && !!(await pending()));

      const rej = await E.decide.execute({ approvalId: a0!.id, tenantId: TENANT, status: "rejected", decidedBy: IR, decidedByRole: "IR_TEAM", comment: "Evaluation: IR rejects this recommended step." });
      const afterRej = await planNow();
      gate("G8", "IR REJECTS the AI recommendation", "ticket → PENDING_MANUAL_DECISION (not executed, not closed)", `${err(rej)}; ticket ${afterRej.status}`, rej.isSuccess && afterRej.status === "PENDING_MANUAL_DECISION");
      const incAfter = await prisma.incident.findUnique({ where: { id: gInc } });
      gate("G9", "a reject does not close or resolve the incident", `incident status unchanged (${incBefore?.status})`, String(incAfter?.status), incAfter?.status === incBefore?.status && incAfter?.status !== "resolved");
      const s2 = await E.start.execute({ responseId: planId, tenantId: TENANT, startedBy: IR });
      gate("G10", "start the response after the reject", "blocked (APPROVAL_PENDING)", err(s2), s2.isFailure);
      gate("G11", "the rejected recommendation was never executed", "0 step executions", `${await stepExec()} step executions`, (await stepExec()) === 0);
      const again = await E.decide.execute({ approvalId: a0!.id, tenantId: TENANT, status: "approved", decidedBy: IR, decidedByRole: "IR_TEAM", comment: "second decision" });
      gate("G12", "decide the same approval twice", "denied (ALREADY_DECIDED)", err(again), again.isFailure && String(again.error) === "ALREADY_DECIDED");
      const md1 = await manual.execute({ responseId: planId, tenantId: TENANT, decidedBy: "SOC", decidedByRole: "SOC", note: "manual plan" });
      gate("G13", "manual decision after reject by a non-IR role", "denied (ROLE_MISMATCH)", err(md1), md1.isFailure && String(md1.error) === "ROLE_MISMATCH");
      const md2 = await manual.execute({ responseId: planId, tenantId: TENANT, decidedBy: IR, decidedByRole: "IR_TEAM", note: null });
      gate("G14", "manual decision by IR without a note", "denied (NOTE_REQUIRED)", err(md2), md2.isFailure && String(md2.error) === "NOTE_REQUIRED");
      const md3 = await manual.execute({ responseId: planId, tenantId: TENANT, decidedBy: IR, decidedByRole: "IR_TEAM", note: "Evaluation: IR writes its own manual response for this step." });
      const afterManual = await planNow();
      gate("G15", "IR records the manual decision after the reject", "ticket → READY_FOR_EXECUTION with a stored IR note; nothing executed automatically", `${err(md3)}; ${afterManual.status}; step executions ${await stepExec()}`, md3.isSuccess && afterManual.status === "READY_FOR_EXECUTION" && (await stepExec()) === 0, { note_stored: !!(afterManual as any).executionResult?.manualDecision?.note });
    }
  }
  const rs = await setStatus.execute({ id: gInc, tenantId: TENANT, status: "resolved", actor: "eval-negative" });
  const incEnd = await prisma.incident.findUnique({ where: { id: gInc } });
  gate("G16", "manually mark the incident RESOLVED (bypassing verification)", "blocked (RESOLVE_REQUIRES_VERIFICATION); status unchanged", `${err(rs)}; status ${incEnd?.status}`, rs.isFailure && String(rs.error) === "RESOLVE_REQUIRES_VERIFICATION" && incEnd?.status === incBefore?.status);

  const summary = {
    unsupported_recommendation_rejection_rate: { numerator: rejectedN, denominator: valid.length, pct: valid.length ? Math.round((rejectedN / valid.length) * 10000) / 100 : null, definition: "rejected invalid recommendations / total invalid recommendations (only scenarios whose positive control validated are counted)" },
    rejected_with_expected_code: { numerator: rejectedExpected, denominator: valid.length },
    scenarios_total: results.length, scenarios_with_failed_control: results.length - valid.length,
    by_layer: { validator: { rejected: valid.filter((r) => r.expected_layer === "VALIDATOR" && r.actual_result === "REJECTED").length, total: valid.filter((r) => r.expected_layer === "VALIDATOR").length }, policy: { rejected: valid.filter((r) => r.expected_layer === "POLICY" && r.actual_result === "REJECTED").length, total: valid.filter((r) => r.expected_layer === "POLICY").length } },
    governance_gates: { passed: gates.filter((g) => g.pass).length, total: gates.length },
    accepted_invalid: valid.filter((r) => r.actual_result === "ACCEPTED").map((r) => r.case_id),
  };
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(path.join(DATA, "negative.json"), JSON.stringify({ evaluation: "C_negative_reject_path", startedAt, finishedAt: new Date().toISOString(), database: pre.db, note: "Controlled invalid recommendations; not a measure of AI accuracy. Part 1 uses the real validator with a positive control per scenario; Part 2 uses the real use cases on the cloned database.", summary, scenarios: results, governance_gates: gates }, null, 2));
  console.log("\nSUMMARY", JSON.stringify(summary));
  await prisma.$disconnect();
})().catch((e) => { console.error("negative crashed:", String(e?.stack ?? e).slice(0, 1500)); process.exit(2); });
