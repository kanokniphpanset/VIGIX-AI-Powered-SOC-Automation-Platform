import { collectLeaves, evalPred } from "./predicate";
import { PlanInstance } from "./planner";
import { KnowledgeBase, StepDef } from "./types";
import { humanizeText, humanizeValue } from "./wording";

/**
 * Runbook step selection + deterministic rendering for ONE plan instance.
 * A step is rendered only if: its variant matches the policy-selected variant, skip_if_eligible is not satisfied by another
 * eligible action, its condition is TRUE for THIS instance's bound targets, and EVERY {{type.field}} resolves to a bound value
 * (otherwise it is omitted and the missing fields are reported - a placeholder never reaches the user).
 */
export interface RenderedStep {
  runbookId: string;
  stepId: string;
  title: string;
  detail: string;
  /** The imperative text of the step (used as a pre-check line when the step is folded). */
  text: string;
  /** How to perform it; null when the knowledge gives none beyond the title. */
  method: string | null;
  impact: string | null;
  verify: string;
  expectedResult: string;
  onFailure: string;
  rollback: string | null;
  manualOwner: string | null;
  fold: boolean;
  isVerifyOnly: boolean;
  /** operation + target identity: two actions asking for the same operation on the same target produce ONE step. */
  dedupeKey: string | null;
  origin: string;
}
export type NotReadyCause = "METHOD_ORG_INPUT" | "METHOD_IR_REVIEW" | "NO_METHOD" | "ORG_DATA" | "PREREQUISITE";
/**
 * Why a step that survived Policy and the condition is still NOT an executable instruction. Action eligibility (Policy) and step readiness
 * are separate: an eligible action may have steps that cannot be performed yet. Such steps go to "information needed" and the audit, never to a Ticket.
 */
export interface OmittedStep { runbookId: string; stepId: string; missing: string[]; reason: "CONDITION" | "PLACEHOLDER" | "TOOL_UNCONFIRMED" | "STEP_NOT_READY"; title?: string; cause?: NotReadyCause; detail?: string }
const ORG_DATA_LABEL: Record<string, string> = { approved_access: "รายการ approved access ขององค์กร (ช่องทาง IR/management ที่ต้องคงไว้)" };
const orgHas = (kb: KnowledgeBase, key: string): boolean => key === "approved_access" ? kb.organization.approvedAccess.length > 0 : false;

const PH = /\{\{\s*([a-z_]+)\.([a-z_]+)\s*\}\}/g;
const has = (v: unknown) => !(v === undefined || v === null || (typeof v === "string" && v.trim() === "") || (Array.isArray(v) && v.length === 0));

export function fillTemplate(text: string, inst: PlanInstance, extra?: Record<string, string>): { text: string; missing: string[] } {
  const missing: string[] = [];
  const out = text.replace(PH, (_m, t: string, f: string) => {
    if (t === "missing") { const v = extra?.[f]; if (v === undefined) missing.push(`missing.${f}`); return v ?? ""; }
    const v = inst.bindings.get(t)?.fields[f];
    if (!has(v)) { missing.push(`${t}.${f}`); return ""; }
    return humanizeValue(f, v);
  });
  return { text: humanizeText(out), missing };
}

/** Fallback title when a step has no explicit `title`: first clause of the instruction (parentheses-aware). */
export function fallbackTitle(text: string): string {
  const re = / เฉพาะ| เพื่อ| โดย| แล้ว| ด้วย| หาก| เมื่อ| เพราะ| — /g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index < 20) continue;
    const before = text.slice(0, m.index);
    if ((before.match(/\(/g) ?? []).length - (before.match(/\)/g) ?? []).length > 0) continue;
    return before.trim();
  }
  return text;
}

/** The part of an instruction that goes beyond its first clause (scope, constraints, method) - shown under an explicit title. */
export function detailAfterFirstClause(text: string): string {
  const re = / เฉพาะ| เพื่อ| โดย| แล้ว| ด้วย| หาก| เมื่อ| เพราะ| — /g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index < 12) continue;
    const before = text.slice(0, m.index);
    if ((before.match(/\(/g) ?? []).length - (before.match(/\)/g) ?? []).length > 0) continue;
    return text.slice(m.index).replace(/^\s*—\s*/, "").trim();
  }
  return "";
}

export function selectSteps(
  kb: KnowledgeBase, runbookId: string, inst: PlanInstance, eligibleActions: ReadonlySet<string>, depth = 0
): { steps: RenderedStep[]; omitted: OmittedStep[] } {
  const rb = kb.runbooks.get(runbookId);
  const steps: RenderedStep[] = [];
  const omitted: OmittedStep[] = [];
  if (!rb || depth > 3) return { steps, omitted };
  const variant = inst.decision.variant ?? "standard";
  const instTypes = new Set([...inst.bindings.values()].filter((t) => t.validated).map((t) => t.type));
  const applicable = new Set(rb.ordered_steps.filter((x) => !x.variant || x.variant === variant).map((x) => x.step_id));
  const readyIds = new Set<string>();
  for (const st of rb.ordered_steps) {
    if (st.variant && st.variant !== variant) continue;
    if ((st.skip_if_eligible ?? []).some((a) => eligibleActions.has(a))) continue;
    if (evalPred(st.condition, inst.facts, instTypes) !== "TRUE") { omitted.push({ runbookId, stepId: st.step_id, missing: [], reason: "CONDITION" }); continue; }
    const body = fillTemplate(st.instruction, inst);
    if (st.requires_confirmed_tool) {
      const caps = collectLeaves(st.condition).filter((l) => l.field.startsWith("capability.")).map((l) => l.field.split(".").slice(1, -1).join("."));
      const unconfirmed = caps.filter((c) => inst.facts.capability.get(c) !== true);
      if (unconfirmed.length) { omitted.push({ runbookId, stepId: st.step_id, missing: unconfirmed, reason: "TOOL_UNCONFIRMED", title: st.title ? fillTemplate(st.title, inst).text : body.text }); continue; }
    }
    const method = st.method ? fillTemplate(st.method, inst) : null;
    const title = st.title ? fillTemplate(st.title, inst) : { text: fallbackTitle(body.text), missing: [] as string[] };
    const missingAll = [...new Set([...body.missing, ...title.missing, ...(method?.missing ?? [])])];
    if (missingAll.length) { omitted.push({ runbookId, stepId: st.step_id, missing: missingAll, reason: "PLACEHOLDER" }); continue; }
    if (st.include_runbook) {
      const sub = selectSteps(kb, st.include_runbook, inst, eligibleActions, depth + 1);
      steps.push(...sub.steps); omitted.push(...sub.omitted);
      continue;
    }
    const verifyOnlyStep = st.kind === "verify" || (!st.fold && /^ตรวจ/.test(st.instruction));
    if (!st.fold && !verifyOnlyStep) {
      // step readiness (operational steps only; folded pre-checks, verify-only and include_runbook steps follow their own rules)
      const notReady = (cause: NotReadyCause, detail: string) => { omitted.push({ runbookId, stepId: st.step_id, missing: [], reason: "STEP_NOT_READY", title: title.text, cause, detail }); };
      if (st.method_basis === "ORG_INPUT_REQUIRED") { notReady("METHOD_ORG_INPUT", st.method_requires ?? "ข้อมูลหรือขั้นตอนเฉพาะขององค์กร"); continue; }
      if (st.method_basis === "IR_REVIEW_REQUIRED") { notReady("METHOD_IR_REVIEW", st.method_requires ?? "การตัดสินใจของ IR"); continue; }
      if (!method && !st.method) { notReady("NO_METHOD", "ความรู้ยังไม่ระบุวิธีลงมือของขั้นตอนนี้"); continue; }
      const orgMissing = (st.requires_org ?? []).filter((k) => !orgHas(kb, k));
      if (orgMissing.length) { notReady("ORG_DATA", orgMissing.map((k) => ORG_DATA_LABEL[k] ?? k).join(", ")); continue; }
      const blockers = (st.needs_prior ?? []).filter((id) => applicable.has(id) && !readyIds.has(id));
      if (blockers.length) { notReady("PREREQUISITE", `ต้องทำหลังขั้นตอนก่อนหน้าที่ยังไม่พร้อม (${blockers.map((id) => { const t = rb.ordered_steps.find((x) => x.step_id === id)?.title; const f = t ? fillTemplate(t, inst) : null; return f && !f.missing.length ? f.text : `ขั้นที่ ${id}`; }).join(", ")})`); continue; }
    }
    readyIds.add(st.step_id);
    const operation = (st as StepDef & { operation?: string; operates_on?: string }).operation;
    const operatesOn = (st as StepDef & { operates_on?: string }).operates_on;
    const bound = operatesOn ? inst.bindings.get(operatesOn) : undefined;
    const verifyOnly = st.kind === "verify" || (!st.fold && /^ตรวจ/.test(st.instruction));
    const detail = st.title ? detailAfterFirstClause(body.text) : body.text.slice(title.text.length).replace(/^\s*(?:—\s*)?/, "").trim();
    steps.push({
      runbookId, stepId: st.step_id, title: title.text, detail, text: body.text, method: method ? method.text : null, impact: st.impact ? fillTemplate(st.impact, inst).text : null, verify: fillTemplate(st.verify, inst).text,
      expectedResult: fillTemplate(st.expected_result, inst).text, onFailure: fillTemplate(st.on_failure, inst).text, rollback: st.rollback ? fillTemplate(st.rollback, inst).text : null,
      manualOwner: st.manual_owner ?? null, fold: !!st.fold, isVerifyOnly: verifyOnly, dedupeKey: operation && bound ? `${operation}|${bound.identityKey}` : null,
      origin: st.origin ?? "EXPANDED_FROM_REFERENCE",
    });
  }
  return { steps, omitted };
}
