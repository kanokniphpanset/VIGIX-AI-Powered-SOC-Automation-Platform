import { ComposedStep, Composition } from "./composer";
import { SubtypePlan } from "./planner";
import { KnowledgeBase } from "./types";
import { RAW_KEY_RE } from "./wording";

/**
 * Output validator. Verifies that what will be shown / stored equals the approved plan:
 *   - every ACTION step is an ELIGIBLE plan instance (same action + same target identity) - nothing added, nothing widened;
 *   - no unresolved placeholders, internal ids, JSON/predicate text, confidence talk, raw secrets, success claims, "follow RB-" steps;
 *   - an LLM candidate may only contribute a summary, and only when it adds no action / target / indicator outside the plan.
 * Violations never create a containment: the caller falls back to the deterministic composition or to "missing information".
 */
const SECRET_PATTERNS: RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/-]{12,}/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/, /\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}/i,
];
const CLAIM_PATTERNS: RegExp[] = [
  /ดำเนินการ(?:เสร็จ)?แล้ว/, /ดำเนินการสำเร็จ/, /สำเร็จแล้ว/, /ยับยั้ง(?:ได้)?สำเร็จ/, /ปิด\s*incident(?:แล้ว)?/i, /\b(?:was|has been|have been|were)\s+(?:executed|contained|blocked|isolated|terminated|quarantined)\b/i,
  /\bsuccessfully\s+(?:executed|contained|blocked|isolated|terminated|quarantined)\b/i, /ระงับ(?:เรียบร้อย|แล้ว)/,
];
/** Statements the knowledge must never assert as fact (accuracy rules): no guarantee about other users, no "deny always/never cuts", no storage claim without an execution record. */
const OVERCLAIM_PATTERNS: RegExp[] = [/ผู้ใช้อื่นไม่ถูกตัด/, /ไม่กระทบผู้ใช้อื่น/, /deny rule ไม่ตัด connection/i, /snapshot เก็บใน incident record/i, /มี metadata ใน incident record/, /มี snapshot สำหรับ/];
const DANGLING_CONDITION_RE = /^\s*(?:วิธีลงมือ:\s*)?หาก\s*control\s*รองรับ\s*$/m;
const INTERNAL_ID_RE = /\b(?:PBK|POL|RB|ACT|PRH|OC|VC|SC)-[A-Z0-9][A-Z0-9-]*\b/;
const PLACEHOLDER_RE = /\{\{[^}]*\}\}|\bTBD\b|<unknown>|\bundefined\b|\[object Object\]/i;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const HASH = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;

export function internalIds(kb: KnowledgeBase): Set<string> {
  const s = new Set<string>();
  for (const k of [kb.actions.keys(), kb.runbooks.keys(), kb.policies.keys(), kb.evidence.keys()]) for (const id of k) s.add(id);
  for (const pb of kb.playbooks.values()) { s.add(pb.subtype_id); s.add(pb.playbook_id); s.add(pb.attack_family); for (const sc of pb.scenarios) s.add(sc.scenario_id); }
  return s;
}

const ID_RE_CACHE = new WeakMap<KnowledgeBase, RegExp>();
function idRegex(kb: KnowledgeBase): RegExp {
  let re = ID_RE_CACHE.get(kb);
  if (!re) {
    const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const ids = [...kb.playbooks.values()].flatMap((p) => [p.subtype_id, p.attack_family, ...p.scenarios.map((x) => x.scenario_id)]).concat([...kb.evidence.keys()]);
    re = new RegExp(`(?<![A-Za-z0-9_-])(?:${[...new Set(ids)].map(esc).join("|")})(?![A-Za-z0-9_-])`);
    ID_RE_CACHE.set(kb, re);
  }
  return re;
}

export function validateUserText(kb: KnowledgeBase, text: string): string[] {
  const v: string[] = [];
  if (PLACEHOLDER_RE.test(text)) v.push("PLACEHOLDER: unresolved placeholder / undefined value in user text");
  if (INTERNAL_ID_RE.test(text)) v.push(`INTERNAL_ID: internal identifier in user text (${INTERNAL_ID_RE.exec(text)?.[0]})`);
  const ids = idRegex(kb).exec(text);
  if (ids) v.push(`INTERNAL_ID: ${ids[0]} in user text`);
  if (/ดำเนินการตาม\s*RB-/.test(text)) v.push("RB_ONLY: step defers to a runbook id");
  for (const re of CLAIM_PATTERNS) if (re.test(text)) { v.push(`UNSUPPORTED_CLAIM: ${re.source}`); break; }
  for (const re of SECRET_PATTERNS) if (re.test(text)) { v.push("RAW_SECRET: secret/token-like value in user text"); break; }
  if (RAW_KEY_RE.test(text)) v.push(`RAW_KEY: internal field/enum key in user text (${RAW_KEY_RE.exec(text)?.[0]})`);
  for (const re of OVERCLAIM_PATTERNS) if (re.test(text)) { v.push(`OVERCLAIM: ${re.source}`); break; }
  if (DANGLING_CONDITION_RE.test(text)) v.push("CONDITION_ONLY: a bare condition ('if the control supports it') is shown as an instruction");
  if (/^[ \t]*-[ \t]*$/m.test(text) || /\*\*ข้อมูลที่ต้องตรวจเพิ่ม\*\*\s*(?:\*\*|$)/.test(text)) v.push("EMPTY_SECTION: an empty heading or bullet in user text");
  if (/confidence|คะแนนความมั่นใจ|similarity|retrieval score/i.test(text)) v.push("CONFIDENCE: confidence / retrieval detail in user text");
  if (/^\s*[{[]\s*"[A-Za-z_]+"\s*:/m.test(text) || /^\s*[a-z_]+:\s*\n\s+- /m.test(text)) v.push("STRUCTURED: JSON/YAML in user text");
  return v;
}

/** Steps and text must be exactly the approved plan: no extra action/target, no step without an eligible instance. */
export function validateComposition(kb: KnowledgeBase, plan: SubtypePlan, comp: Composition): string[] {
  const v: string[] = [];
  const eligible = new Map(plan.ordered.map((n) => [n.instanceKey, n]));
  const seen = new Set<string>();
  for (const s of comp.steps) {
    if (s.stepType === "ACTION") {
      const inst = s.instanceKey ? eligible.get(s.instanceKey) : undefined;
      if (!inst) { v.push(`NOT_IN_PLAN: step ${s.actionCode} / ${s.target} is not an eligible plan instance`); continue; }
      if (inst.action_id !== s.actionCode) v.push(`ACTION_MISMATCH: ${s.actionCode} != ${inst.action_id}`);
      if ((inst.primary?.display ?? null) !== s.target) v.push(`TARGET_MISMATCH: ${s.target} != ${inst.primary?.display}`);
      if (seen.has(s.instanceKey!)) v.push(`DUPLICATE: ${s.instanceKey}`);
      seen.add(s.instanceKey!);
      if (!s.instructions.some((i) => i.kind === "action")) v.push(`EMPTY_ACTION: ${s.actionCode} has no executable instruction`);
    }
    if ((s.stepType === "CHECK" || s.stepType === "MANUAL") && s.actionCode) v.push(`TYPE_MISMATCH: ${s.stepType} step names an action`);
  }
  v.push(...validateUserText(kb, comp.userText));
  return v;
}

export interface CandidateReview { accepted: boolean; summary: string | null; deviations: string[] }

/**
 * An (unvalidated) AI candidate is reviewed against the approved plan. It can never add or change actions, targets or scope:
 * any deviation rejects its contribution; an acceptable candidate only supplies the one-line summary.
 */
export function reviewCandidate(kb: KnowledgeBase, plan: SubtypePlan, candidate: unknown, allowedValues: ReadonlySet<string>): CandidateReview {
  const c = (candidate && typeof candidate === "object" ? candidate : {}) as { summary?: unknown; steps?: unknown };
  const deviations: string[] = [];
  const actions = new Set(plan.ordered.flatMap((n) => [n.action_id, ...(kb.actions.get(n.action_id)?.legacy_action_refs ?? [])]));
  const targets = new Set(plan.ordered.flatMap((n) => [...n.bindings.values()].flatMap((t) => [t.display, ...Object.values(t.fields).flat().map(String)])).concat([...allowedValues]));
  for (const st of Array.isArray(c.steps) ? (c.steps as { action?: unknown; target?: unknown; type?: unknown }[]) : []) {
    if (typeof st.action === "string" && st.action && !actions.has(st.action)) deviations.push(`EXTRA_ACTION: ${st.action} is not an approved action`);
    if (typeof st.target === "string" && st.target && !targets.has(st.target)) deviations.push(`EXPANDED_SCOPE: target ${st.target} is not an approved target`);
  }
  let summary: string | null = typeof c.summary === "string" && c.summary.trim() ? c.summary.trim().slice(0, 400) : null;
  if (summary) {
    const bad = validateUserText(kb, summary);
    const known = new Set([...targets].map((t) => t.toLowerCase()));
    const extra = [...(summary.match(IPV4) ?? []), ...(summary.match(HASH) ?? [])].filter((x) => !known.has(x.toLowerCase()));
    if (bad.length) deviations.push(...bad.map((b) => `SUMMARY_${b}`));
    if (extra.length) deviations.push(`SUMMARY_UNGROUNDED_INDICATOR: ${extra.join(",")}`);
    if (bad.length || extra.length) summary = null;
  }
  return { accepted: deviations.length === 0 && !!summary, summary: deviations.length ? null : summary, deviations };
}

export type { ComposedStep };
