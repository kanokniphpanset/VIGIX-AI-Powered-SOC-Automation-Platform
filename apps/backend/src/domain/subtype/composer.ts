import { PlanInstance, SubtypePlan } from "./planner";
import { collectLeaves } from "./predicate";
import { OmittedStep, RenderedStep, selectSteps } from "./steps";
import { KnowledgeBase } from "./types";
import { labelOfCapability, labelOfField } from "./wording";

/**
 * Deterministic recommendation composer. Final wording comes ONLY from approved plan + validated targets + Runbook steps.
 * Produces (1) persistable steps (ACTION = ticketable and ready, MANUAL = needs a named approval, CHECK = information needed /
 * status notes) and (2) the user-facing text in the contract format. Internal ids, predicates, confidence and audit never appear.
 *
 * The user text keeps four groups apart: ready steps (workflow-ready, IR executes), actions needing approval, information needed,
 * and the status of earlier measures. An action that lacks evidence, target, authority or a confirmed tool is never a ready step.
 */
export interface ComposedInstruction {
  order: number;
  /** Legacy single-string form (title + method) kept for tickets / guides that only know `instruction`. */
  instruction: string;
  target: string | null;
  expectedResult: string | null;
  title: string;
  impact: string | null;
  verify: string | null;
  kind: "action" | "verify";
  manualOwner: string | null;
  /** How to perform it (scope, flow/session identification). */
  method?: string | null;
  /** 'method' = explicit how-to from the runbook; 'detail' = text derived after the title (shown as plain details, not as a method). */
  methodKind?: "method" | "detail";
  /** Checks to make BEFORE acting; imperative text, never a claim that something already exists. */
  preconditions?: string[];
  rollback?: string | null;
  /** Why this is proposed again (failed / threat returned) - set on the first instruction of such an instance. */
  note?: string | null;
}
export interface ComposedStep {
  stepType: "ACTION" | "CHECK" | "MANUAL";
  title: string;
  objective: string;
  actionCode: string | null;
  target: string | null;
  reason: string;
  evidenceRefs: string[];
  runbookCode: string | null;
  precondition: string | null;
  expectedResult: string | null;
  requiresApproval: boolean;
  verificationCriteria: string | null;
  instructions: ComposedInstruction[];
  instanceKey: string | null;
}
export interface Composition {
  steps: ComposedStep[];
  omitted: { instanceKey: string; omitted: OmittedStep[] }[];
  /** specific data still needed (evidence confirm instructions / target fields / ambiguity / tool), never invented. */
  missingInfo: string[];
  userText: string;
  summary: string;
  /** Per action instance: which steps are executable and which are not (and why). Action eligibility (Policy) does not imply step readiness. */
  readiness: { instanceKey: string; action: string; target: string | null; ready: string[]; notReady: { step: string; title: string; cause: string; detail: string }[] }[];
}

export const AUTH_LABEL: Record<string, string> = {
  ir_emergency: "IR (อำนาจเร่งด่วน)", dba: "DBA", business_authority: "ผู้มีอำนาจของรายการธุรกิจ", asset_owner: "เจ้าของ asset/workload",
  change_approval: "ผู้อนุมัติ change/control", ir_execute: "IR (ผู้ดำเนินการ)",
};
const IMPACT_APPROVAL = new Set(["HIGH", "CRITICAL"]);
const actionLabel = (a?: { label_th?: string; action_name: string }) => a?.label_th ?? a?.action_name;
/** Titles that identify the non-action steps when stored steps are rendered again (API). */
export const MISSING_TITLE = "ข้อมูลที่ต้องตรวจเพิ่ม";
export const NOTES_TITLE = "สถานะมาตรการจากรอบก่อน";
export const EXPLAIN_TITLE = "สรุปสถานะ";
export const TOOL_NOTE_TITLE = "หมายเหตุเรื่องเครื่องมือ";
/** @deprecated kept so older stored recommendations still render; new ones use MISSING_TITLE. */
export const INVESTIGATE_TITLE = "ตรวจสอบเพิ่มเติมก่อนกำหนดมาตรการ";
/** Generic "confirm the alert" line used when nothing more specific is known (the preview replaces it with specific gaps). */
export const GENERIC_CONFIRM = "ยืนยันหลักฐานที่ทำให้เกิดการแจ้งเตือน (สถานะ เวลา และ entity) จาก log ที่มีอยู่ โดยไม่ execute script/binary ที่น่าสงสัย";

const TOOL_NOTE = "องค์กรยังไม่ได้ระบุเครื่องมือ/คำสั่ง/เมนูที่ใช้ลงมือในระบบ ข้อความข้างต้นจึงระบุเฉพาะขอบเขต เงื่อนไข และผลที่ต้องตรวจ — IR ใช้เครื่องมือขององค์กรให้ตรงตามนั้น";
const NOT_READY_PREFIX: Record<string, string> = { METHOD_ORG_INPUT: "ต้องมีข้อมูลหรือขั้นตอนเฉพาะขององค์กร — ", METHOD_IR_REVIEW: "รอ IR กำหนด — ", NO_METHOD: "", ORG_DATA: "ต้องระบุ ", PREREQUISITE: "" };
const SNAPSHOT_RE = /snapshot/i;
const NO_SNAPSHOT_ROLLBACK = "คืนค่าเดิมที่บันทึกด้วยมือก่อนแก้ (ยังไม่ระบุเครื่องมือเก็บ snapshot ในระบบ)";

const checkStep = (title: string, objective: string, reason: string, items: string[]): ComposedStep => ({
  stepType: "CHECK", title, objective, actionCode: null, target: null, reason, evidenceRefs: [], runbookCode: null, precondition: null, expectedResult: null,
  requiresApproval: false, verificationCriteria: null, instanceKey: null,
  instructions: items.map((t, i) => ({ order: i + 1, instruction: t, target: null, expectedResult: null, title: t, impact: null, verify: null, kind: "action" as const, manualOwner: null })),
});

export function composePlan(kb: KnowledgeBase, plan: SubtypePlan, evidenceRefOf: (ids: string[]) => string[] = (x) => x): Composition {
  const steps: ComposedStep[] = [];
  const omitted: Composition["omitted"] = [];
  const missingInfo: string[] = [];
  const readiness: Composition["readiness"] = [];
  const eligibleActions = new Set(plan.ordered.map((n) => n.action_id));
  const seenOps = new Set<string>();
  const targetLabel = (t: string) => kb.targetTypes.get(t)?.label_th ?? t;
  let toolMapping = false;

  for (const inst of plan.ordered) {
    const action = kb.actions.get(inst.action_id)!;
    if (action.phase !== "CONTAINMENT") continue;
    const instructions: ComposedInstruction[] = [];
    let pending: string[] = [];
    const preconditionAll: string[] = [];
    const instOmitted: OmittedStep[] = [];
    let runbookCode: string | null = null;
    const snapshotKnown = inst.facts.capability.get("cap.config_snapshot") === true;
    for (const rb of action.runbook_refs) {
      runbookCode = runbookCode ?? rb;
      const sel = selectSteps(kb, rb, inst, eligibleActions);
      instOmitted.push(...sel.omitted);
      for (const s of sel.steps) {
        if (s.dedupeKey) { if (seenOps.has(s.dedupeKey)) continue; seenOps.add(s.dedupeKey); }
        if (s.fold) { pending.push(s.text); continue; }
        if (s.isVerifyOnly) { instructions.push(toInstruction(s, instructions.length + 1, inst, "verify", [], snapshotKnown)); continue; }
        const ins = toInstruction(s, instructions.length + 1, inst, "action", pending, snapshotKnown);
        preconditionAll.push(...pending); pending = [];
        instructions.push(ins);
      }
    }
    omitted.push({ instanceKey: inst.instanceKey, omitted: instOmitted });
    for (const o of instOmitted) {
      if (o.reason === "PLACEHOLDER") for (const m of o.missing) if (!m.startsWith("missing.")) { const [t, f] = m.split("."); missingInfo.push(`${targetLabel(t)}: ต้องระบุ${labelOfField(f)}`); }
      if (o.reason === "STEP_NOT_READY") missingInfo.push(`ขั้นตอน "${o.title}" ยังไม่พร้อมลงมือ: ${NOT_READY_PREFIX[o.cause ?? "NO_METHOD"]}${o.detail}`);
      if (o.reason === "TOOL_UNCONFIRMED") missingInfo.push(`เครื่องมือที่ใช้ "${o.title}" (${o.missing.map(labelOfCapability).join(", ")}) ยังไม่ได้ระบุว่ารองรับ และต้องทราบตัวระบุ session/connection ตามเครื่องมือนั้น จึงยังไม่แสดงเป็นขั้นตอนพร้อมลงมือ`);
    }
    readiness.push({
      instanceKey: inst.instanceKey, action: inst.action_id, target: inst.primary?.display ?? null,
      ready: instructions.filter((i) => i.kind === "action").map((i) => i.title),
      notReady: instOmitted.filter((o) => o.reason === "STEP_NOT_READY" || o.reason === "TOOL_UNCONFIRMED").map((o) => ({ step: `${o.runbookId}|${o.stepId}`, title: o.title ?? "", cause: o.cause ?? o.reason, detail: o.detail ?? o.missing.join(", ") })),
    });
    const actionable = instructions.filter((i) => i.kind === "action");
    if (!actionable.length) { missingInfo.push(`ขั้นตอนของมาตรการ "${actionLabel(action)}" ยังไม่มีข้อมูลเพียงพอที่จะลงมือได้`); continue; }
    if ((inst.state === "EXECUTED_NOT_APPLIED" || inst.state === "FAILED") && inst.stateReason) actionable[0].note = inst.stateReason;
    if (inst.decision.flags.includes("TOOL_MAPPING_REQUIRED")) toolMapping = true;
    steps.push({
      stepType: "ACTION", title: actionable[0].title, objective: action.objective, actionCode: action.action_id, target: inst.primary?.display ?? null,
      reason: [inst.orderReason, inst.stateReason].filter(Boolean).join(" | "),
      evidenceRefs: evidenceRefOf([...new Set([...inst.bindings.values()].flatMap((t) => t.evidenceRefs))]),
      runbookCode, precondition: preconditionAll.length ? [...new Set(preconditionAll)].join(" / ") : null, expectedResult: actionable[actionable.length - 1].expectedResult,
      requiresApproval: IMPACT_APPROVAL.has(action.impact_level ?? "MEDIUM") || inst.decision.variant !== null,
      verificationCriteria: kb.runbooks.get(runbookCode ?? "")?.verification.join(" / ") ?? null,
      instructions: renumber(instructions), instanceKey: inst.instanceKey,
    });
  }

  // not-eligible actions: never a ready step. What is needed to open them is stated separately.
  const authSeen = new Set<string>();
  let authorizedNote = false;
  let evidenceGap = false;
  let targetGap = false;
  let approvals = 0;
  for (const n of plan.notEligible) {
    const d = n.decision;
    if (d.reasons.some((r) => r.code.startsWith("AUTHORIZED:"))) authorizedNote = true;
    if (d.decision === "NEEDS_EVIDENCE") { evidenceGap = true; for (const e of d.missing_evidence) { const ev = kb.evidence.get(e); if (ev) missingInfo.push(`${ev.confirm} (เพื่อเปิดมาตรการ: ${actionLabel(kb.actions.get(n.action_id))})`); } }
    if (d.decision === "NEEDS_TARGET") {
      targetGap = true;
      for (const t of d.missing_targets) missingInfo.push(`${targetLabel(t)}: ต้องระบุ ${(kb.targetTypes.get(t)?.required_identity_fields ?? []).map(labelOfField).join(", ")}`);
      for (const t of n.ambiguous) missingInfo.push(`${targetLabel(t)}: พบหลายรายการที่เป็นไปได้ ต้องระบุให้ชัดว่าเป็นรายการใด`);
    }
    if (d.decision === "UNSUPPORTED") { targetGap = true; missingInfo.push(`เครื่องมือที่รองรับมาตรการ "${actionLabel(kb.actions.get(n.action_id))}" ยังไม่รองรับหรือยังไม่ได้ระบุ`); }
    if (d.decision === "NEEDS_AUTHORIZATION" && !authSeen.has(`${n.action_id}|${n.primary?.display ?? ""}`)) {
      authSeen.add(`${n.action_id}|${n.primary?.display ?? ""}`);
      approvals++;
      steps.push(approvalStep(kb, n));
    }
  }

  // suppressed (still effective / awaiting verification / ticket open) -> explicit status; UNKNOWN states name what is missing
  const notes: string[] = [];
  let effective = 0, unverified = 0, pendingTicket = 0, adjust = 0;
  for (const s of plan.suppressed) {
    const a = kb.actions.get(s.action_id)!;
    notes.push(`${actionLabel(a)}${s.primary ? ` (${s.primary.display})` : ""}: ${s.stateReason}`);
    if (s.state === "EXECUTED_EFFECTIVE") effective++;
    if (s.state === "RECURRED_CONTROL_APPLIED") adjust++;
    if (s.state === "EXECUTED_UNVERIFIED" || s.state === "RECURRED_CONTROL_UNKNOWN" || s.state === "RECURRED_CONTROL_APPLIED") { unverified++; missingInfo.push(...(s.stateNeeds.length ? s.stateNeeds : [`ผลยืนยันของมาตรการ ${actionLabel(a)}`])); }
    if (s.state === "PROPOSED_PENDING") pendingTicket++;
  }

  const containment = steps.filter((s) => s.stepType === "ACTION");
  const uniqueMissing = [...new Set(missingInfo)];
  const hasStatus = notes.length > 0;
  // An explanation names the REAL reason nothing is ready. "Evidence is insufficient" is said only when evidence is what is missing.
  if (!containment.length) {
    let explain: string;
    if (authorizedNote) explain = "หลักฐานระบุว่ากิจกรรมที่ตรวจพบได้รับอนุมัติ (approved) จึงไม่เปิดมาตรการ containment — ให้ยืนยันกับ change record/เจ้าของงานก่อน หากพบว่าไม่ได้รับอนุมัติจริงจึงประเมินใหม่";
    else if (approvals) explain = "มาตรการที่ผ่านเงื่อนไขหลักฐานแล้วยังต้องได้รับอนุมัติก่อน จึงยังไม่มีขั้นตอนที่พร้อมลงมือ";
    else if (evidenceGap) explain = "ยังไม่มีขั้นตอนที่พร้อมลงมือ เพราะหลักฐานยังไม่พอจะยืนยันเงื่อนไขของมาตรการ";
    else if (targetGap) explain = "ยังไม่มีขั้นตอนที่พร้อมลงมือ เพราะขาดข้อมูลเป้าหมาย จุดควบคุม หรือเครื่องมือขององค์กร (หลักฐานที่มีผ่านเงื่อนไขของมาตรการแล้ว)";
    else if (hasStatus && adjust) explain = "พบกิจกรรมกลับมาหลังมาตรการเดิมถูกนำไปใช้ จึงไม่เสนอทำมาตรการเดิมซ้ำ — ให้ตรวจเส้นทางหรือขอบเขตที่กิจกรรมใหม่ใช้ก่อนประเมินปรับหรือเพิ่มมาตรการ (ดูสถานะและข้อมูลที่ต้องตรวจเพิ่ม)";
    else if (hasStatus && unverified) explain = "ยังไม่เสนอมาตรการซ้ำ เพราะยังยืนยันผลของมาตรการเดิมไม่ได้ (ไม่ถือว่า contained และไม่ถือว่าล้มเหลว)";
    else if (hasStatus && effective && !unverified && !pendingTicket) explain = "ไม่มีมาตรการใหม่ที่ต้องเสนอในรอบนี้ เพราะมาตรการเดิมยังมีผลตามผล Re-hunt ล่าสุด";
    else if (hasStatus) explain = "ไม่มีมาตรการใหม่ที่ต้องเสนอในรอบนี้ ตามสถานะของมาตรการจากรอบก่อนด้านล่าง";
    else explain = "ยังไม่พบหลักฐานที่ยืนยันประเภทภัยจนเปิดมาตรการ containment ได้ (สิ่งที่พบอาจเป็นเพียง indicator)";
    steps.push(checkStep(EXPLAIN_TITLE, "อธิบายเหตุที่ยังไม่มีขั้นตอนพร้อมลงมือ", "สรุปจากผลประเมิน policy", [explain]));
    if (!uniqueMissing.length && !hasStatus && !approvals && !authorizedNote) uniqueMissing.push(GENERIC_CONFIRM);
  }
  if (uniqueMissing.length) steps.push(checkStep(MISSING_TITLE, "ข้อมูลที่ยังขาดสำหรับมาตรการ", "ข้อมูลที่ยังไม่ครบ ไม่ถูกเติมเอง", uniqueMissing));
  if (notes.length) steps.push(checkStep(NOTES_TITLE, "สถานะของมาตรการที่เสนอ/ดำเนินการไปแล้วในรอบก่อน", "จาก Response Ticket และผล Re-hunt จริงของรอบก่อน", notes));
  if (containment.length && toolMapping) steps.push(checkStep(TOOL_NOTE_TITLE, "เครื่องมือที่ใช้ลงมือ", "องค์กรยังไม่ระบุเครื่องมือ", [TOOL_NOTE]));

  const summary = containment.length
    ? `ข้อเสนอมาตรการยับยั้ง ${containment.length} รายการ เรียงตามลำดับและเงื่อนไขที่ผ่านการตรวจหลักฐาน/target แล้ว (ยังไม่มีการดำเนินการจริง; รอ SOC ตรวจและ IR ลงมือ)`
    : hasStatus && !targetGap && !evidenceGap && !approvals ? "ไม่มีมาตรการใหม่ที่ต้องเสนอในรอบนี้ — ดูสถานะมาตรการจากรอบก่อนและข้อมูลที่ต้องตรวจเพิ่ม"
    : "ยังไม่มีขั้นตอนที่พร้อมลงมือ — ดูเหตุผลและข้อมูลที่ต้องตรวจเพิ่ม";
  return { steps, omitted, missingInfo: uniqueMissing, userText: renderUserText(steps), summary, readiness };
}

/** Roles whose authority the action still needs (from the policy, and only roles the knowledge actually names). */
function approvalStep(kb: KnowledgeBase, n: PlanInstance): ComposedStep {
  const d = n.decision;
  const action = kb.actions.get(n.action_id)!;
  const roles = new Set<string>();
  for (const r of d.reasons) { const m = /(asset_owner|change_approval|dba|business_authority|ir_emergency|ir_execute)/.exec(`${r.code} ${r.detail}`); if (m) roles.add(m[1]); }
  for (const p of kb.policies.values()) if (p.rule_type === "ACTION_GATE" && p.action_id === n.action_id)
    for (const l of collectLeaves(p.authority_requirements)) if (l.field.startsWith("authority.")) { const role = l.field.split(".")[1]; if (n.facts.authority.get(role) !== true) roles.add(role); }
  const names = [...roles].map((r) => AUTH_LABEL[r] ?? r);
  const contacts = [...roles].map((r) => kb.organization.authorityContacts[r]).filter((c): c is string => !!c);
  const why = d.reasons.some((r) => /CRIT_AUTH/.test(r.code)) ? " (asset/workload ที่เกี่ยวข้องมีความสำคัญสูง)" : "";
  const label = actionLabel(action)!;
  const text = `${label}${n.primary ? ` (${n.primary.display})` : ""}: ต้องได้รับอนุมัติจาก ${names.join(", ") || "ผู้มีอำนาจที่เกี่ยวข้อง"} ก่อนจึงจะเป็นขั้นตอนพร้อมลงมือ${why}; ${contacts.length ? `ผู้ติดต่อที่องค์กรระบุ: ${contacts.join(", ")}` : "องค์กรยังไม่ได้ระบุผู้รับหรือช่องทางอนุมัติในระบบ"}`;
  return {
    stepType: "MANUAL", title: `ขออนุมัติก่อนดำเนินการ: ${label}`, objective: action.objective, actionCode: null, target: n.primary?.display ?? null,
    reason: "มาตรการนี้ผ่านเงื่อนไขหลักฐานแล้วแต่ยังขาดอำนาจ/การอนุมัติที่ระบบตรวจยืนยันได้ จึงยังไม่เป็นขั้นตอนพร้อมลงมือ",
    evidenceRefs: [], runbookCode: null, precondition: null, expectedResult: null, requiresApproval: true, verificationCriteria: null, instanceKey: null,
    instructions: [{ order: 1, instruction: text, target: n.primary?.display ?? null, expectedResult: null, title: `ขออนุมัติ ${label}`, impact: null, verify: null, kind: "action", manualOwner: [...roles][0] ?? null }],
  };
}

function toInstruction(s: RenderedStep, order: number, inst: PlanInstance, kind: "action" | "verify", preconditions: string[], snapshotKnown: boolean): ComposedInstruction {
  const method = (s.method ?? s.detail) || null;
  const rollback = s.rollback && SNAPSHOT_RE.test(s.rollback) && !snapshotKnown ? NO_SNAPSHOT_ROLLBACK : s.rollback;
  return {
    order, title: s.title, instruction: method ? `${s.title} ${method}`.trim() : s.title, target: inst.primary?.display ?? null, expectedResult: s.expectedResult,
    impact: s.impact, verify: s.verify, kind, manualOwner: s.manualOwner, method, preconditions: [...new Set(preconditions)], rollback, note: null, methodKind: s.method ? "method" : "detail",
  };
}
const renumber = (ins: ComposedInstruction[]) => ins.map((i, n) => ({ ...i, order: n + 1 }));

type RenderIn = { stepType: string; title: string; instructions: Pick<ComposedInstruction, "title" | "instruction" | "impact" | "verify" | "kind" | "manualOwner" | "method" | "methodKind" | "preconditions" | "rollback" | "note">[] };
const bullets = (steps: RenderIn[], title: string) => steps.filter((s) => s.stepType === "CHECK" && s.title === title).flatMap((s) => s.instructions.map((i) => i.instruction));

/** The ONE renderer of the user-facing contract; also used by the API to render stored steps. */
export function renderUserText(steps: RenderIn[]): string {
  const L: string[] = ["**คำแนะนำเพื่อยับยั้ง Incident**", ""];
  const explain = bullets(steps, EXPLAIN_TITLE);
  const notes = bullets(steps, NOTES_TITLE);
  const actions = steps.filter((s) => s.stepType === "ACTION");
  const approvals = steps.filter((s) => s.stepType === "MANUAL");
  const missing = [...bullets(steps, MISSING_TITLE), ...bullets(steps, INVESTIGATE_TITLE)];
  const toolNote = bullets(steps, TOOL_NOTE_TITLE);

  if (explain.length) L.push(...explain, "");
  if (notes.length) L.push("**สถานะมาตรการจากรอบก่อน**", ...notes.map((t) => `- ${t}`), "");

  const verify: string[] = [];
  let n = 0;
  for (const s of actions) for (const i of s.instructions) {
    if (i.kind === "verify") { verify.push(i.instruction); continue; }
    n++;
    L.push(`${n}. **${i.title}**`);
    if (i.manualOwner) L.push(`   ผู้รับผิดชอบ: ${AUTH_LABEL[i.manualOwner] ?? i.manualOwner} (ดำเนินการโดยผู้มีอำนาจ — IR ไม่ดำเนินการแทน)`);
    const method = i.method !== undefined ? i.method : (i.instruction.startsWith(i.title) ? i.instruction.slice(i.title.length).trim() : i.instruction);
    if (method) L.push(`   ${i.methodKind === "detail" ? "รายละเอียด" : "วิธีลงมือ"}: ${method}`);
    if (i.preconditions?.length) L.push("   ก่อนลงมือ:", ...i.preconditions.map((p) => `   - ${p}`));
    if (i.impact) L.push(`   *ผลกระทบ: ${i.impact}*`);
    if (i.verify) L.push(`   *ตรวจผล: ${i.verify}*`);
    if (i.rollback) L.push(`   ย้อนกลับ: ${i.rollback}`);
    if (i.note) L.push(`   เหตุผลที่เสนออีกครั้ง: ${i.note}`);
    L.push("");
  }
  if (actions.length && verify.length) L.push("**ตรวจผลรวมหลังดำเนินการ**", ...[...new Set(verify)].map((v) => `- ${v}`), "");
  if (approvals.length) L.push("**ต้องขออนุมัติก่อนดำเนินการ (ยังไม่ใช่ขั้นตอนพร้อมลงมือ)**", ...approvals.flatMap((a) => a.instructions.map((i) => `- ${i.instruction}`)), "");
  if (missing.length) L.push("**ข้อมูลที่ต้องตรวจเพิ่ม**", ...missing.map((t) => `- ${t}`), "");
  if (toolNote.length) L.push("**หมายเหตุเรื่องเครื่องมือ**", ...toolNote, "");
  return L.join("\n").trimEnd() + "\n";
}
