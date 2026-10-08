// lib.mjs — loader + 3-valued predicate engine + policy evaluator + planner for subtype-playbooks knowledge.
// Prototype of the RUNTIME components that must exist in the RAG agent (policy evaluator, dependency ordering, step selector).
// Data-only knowledge never executes; this file is the reference semantics that validate.mjs/evaluate.mjs test against.
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const yaml = require("js-yaml");

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readYaml = (p) => yaml.load(fs.readFileSync(p, "utf8"));

export function loadAll() {
  const registry = readYaml(path.join(ROOT, "reference/reference-registry.yaml"));
  const targetTypes = readYaml(path.join(ROOT, "contracts/target-types.yaml")).target_types;
  const dictionary = readYaml(path.join(ROOT, "contracts/field-dictionary.yaml"));
  const orgContext = readYaml(path.join(ROOT, "contracts/organization-context.yaml"));
  const famDir = path.join(ROOT, "families");
  const files = fs.readdirSync(famDir).filter((f) => f.endsWith(".yaml")).sort();
  const families = files.map((f) => ({ file: f, ...readYaml(path.join(famDir, f)) }));
  const casesPath = path.join(ROOT, "validation/cases.yaml");
  const cases = fs.existsSync(casesPath) ? readYaml(casesPath).cases : [];
  const kb = { registry, targetTypes, dictionary, orgContext, families, cases, evidence: new Map(), actions: new Map(), policies: new Map(), playbooks: new Map(), runbooks: new Map(), dup: [] };
  const put = (map, key, val, kind, file) => { if (map.has(key)) kb.dup.push(`${kind} ${key} (${file})`); map.set(key, { ...val, __file: file }); };
  for (const f of families) {
    for (const e of f.evidence ?? []) put(kb.evidence, e.id, e, "evidence", f.file);
    for (const a of f.actions ?? []) put(kb.actions, a.action_id, a, "action", f.file);
    for (const p of f.policies ?? []) put(kb.policies, p.policy_id, p, "policy", f.file);
    for (const p of f.playbooks ?? []) put(kb.playbooks, p.subtype_id, p, "playbook", f.file);
    for (const r of f.runbooks ?? []) put(kb.runbooks, r.runbook_id, r, "runbook", f.file);
  }
  return kb;
}

// ---------------------------------------------------------------- facts ----------------------------------------------
/** Compact case facts -> normalized facts. evidence: {id: "STATUS[/AUTH]"}; targets: [types]; scope:[flags]; authority:[ids]; capability:{supported:[],unsupported:[]}. */
export function normalizeFacts(raw = {}, orgDefaults = {}) {
  const f = { fieldsMissing: new Set(raw.fields_missing ?? []), mode: raw.mode ?? "platform_neutral", evidence: {}, targets: new Set(raw.targets ?? []), scope: new Set(raw.scope ?? []), authority: new Map(), capability: new Map(), context: { ...(raw.context ?? {}) } };
  for (const [id, v] of Object.entries(raw.evidence ?? {})) {
    const [status, auth] = String(v).split("/");
    f.evidence[id] = { status: status || "UNKNOWN", authorization_status: auth || "UNKNOWN" };
  }
  f.authority.set("ir_execute", orgDefaults.ir_execute ?? true);
  for (const a of raw.authority ?? []) f.authority.set(a, true);
  for (const a of raw.authority_denied ?? []) f.authority.set(a, false);
  for (const c of raw.capability?.supported ?? []) f.capability.set(c, true);
  for (const c of raw.capability?.unsupported ?? []) f.capability.set(c, false);
  return f;
}

// ---------------------------------------------------------------- predicates ----------------------------------------
export const T = "TRUE", F = "FALSE", U = "UNKNOWN";

export function getField(field, facts) {
  const p = field.split(".");
  switch (p[0]) {
    case "evidence": { const e = facts.evidence[p[1]]; if (!e) return undefined; return e[p[2]]; }
    case "targets": return facts.targets.has(p[1]) ? true : (facts.targetsUnknown?.has?.(p[1]) ? undefined : false);
    case "scope": return facts.scope.has(p[1]) ? true : false;
    case "authority": return facts.authority.has(p[1]) ? facts.authority.get(p[1]) : undefined;
    case "capability": { const id = p.slice(1, -1).join("."); if (facts.capability.has(id)) return facts.capability.get(id); return facts.mode === "strict" ? undefined : true; }
    case "context": return facts.context[field];
    default: return undefined;
  }
}

export function evalLeaf(leaf, facts) {
  const v = getField(leaf.field, facts);
  if (v === undefined || v === null || v === "UNKNOWN") return U;
  const want = leaf.value;
  switch (leaf.operator) {
    case "equals": return v === want ? T : F;
    case "not_equals": return v !== want ? T : F;
    case "in": return want.includes(v) ? T : F;
    case "not_in": return !want.includes(v) ? T : F;
    case "gte": return v >= want ? T : F;
    case "lte": return v <= want ? T : F;
    default: throw new Error(`bad operator ${leaf.operator}`);
  }
}

export function evalPred(pred, facts) {
  if (pred === undefined || pred === null) return T;
  if (pred.field) return evalLeaf(pred, facts);
  if (pred.all_of) { const rs = pred.all_of.map((p) => evalPred(p, facts)); return rs.includes(F) ? F : rs.includes(U) ? U : T; }
  if (pred.any_of) { const rs = pred.any_of.map((p) => evalPred(p, facts)); return rs.includes(T) ? T : rs.includes(U) ? U : F; }
  if (pred.none_of) { const rs = pred.none_of.map((p) => evalPred(p, facts)); return rs.includes(T) ? F : rs.includes(U) ? U : T; }
  throw new Error("bad predicate " + JSON.stringify(pred));
}

export function collectLeaves(pred, out = []) {
  if (!pred || typeof pred !== "object") return out;
  if (pred.field) { out.push(pred); return out; }
  for (const k of ["all_of", "any_of", "none_of"]) if (pred[k]) for (const p of pred[k]) collectLeaves(p, out);
  return out;
}

// ---------------------------------------------------------------- policy evaluator ----------------------------------
const FAIL_RANK = ["PROHIBITED", "NEEDS_EVIDENCE", "NEEDS_TARGET", "NEEDS_AUTHORIZATION", "UNSUPPORTED"];

export function evaluateAction(kb, actionId, subtype, facts, mode = "platform_neutral") {
  const policies = [...kb.policies.values()].filter((p) => p.rule_type === "ACTION_GATE" && p.action_id === actionId && (p.applicable_subtypes.includes("*") || p.applicable_subtypes.includes(subtype)));
  const res = { action_id: actionId, subtype, policies: policies.map((p) => p.policy_id), reasons: [], failing: new Set(), flags: new Set(), variant: null, missing_evidence: new Set(), missing_targets: new Set() };
  if (!policies.length) { res.failing.add("PROHIBITED"); res.reasons.push({ code: "NO_POLICY", detail: `no ACTION_GATE policy for ${actionId} in ${subtype} (fail closed)` }); return finish(res); }
  const gp = [...kb.policies.values()].filter((p) => p.rule_type === "GLOBAL_PROHIBITION");
  for (const g of gp) for (const pr of g.prohibitions) if (evalPred(pr.when, facts) === T) { res.failing.add("PROHIBITED"); res.reasons.push({ code: pr.id, detail: pr.reason }); }
  for (const p of policies) {
    for (const pr of p.prohibitions ?? []) if (evalPred(pr.when, facts) === T) { res.failing.add("PROHIBITED"); res.reasons.push({ code: pr.id, detail: pr.reason }); }
    for (const ev of p.authorization_gate ?? []) {
      const e = facts.evidence[ev];
      if (e?.authorization_status === "AUTHORIZED") { res.failing.add("PROHIBITED"); res.reasons.push({ code: `AUTHORIZED:${ev}`, detail: `evidence ${ev} is AUTHORIZED (approved/benign activity)` }); }
      else if (e?.authorization_status !== "UNAUTHORIZED") { res.failing.add("NEEDS_EVIDENCE"); res.missing_evidence.add(ev); res.reasons.push({ code: `AUTHZ_UNKNOWN:${ev}`, detail: `authorization of ${ev} not established` }); }
    }
    if (evalPred(p.required_evidence, facts) !== T) {
      res.failing.add("NEEDS_EVIDENCE");
      for (const l of collectLeaves(p.required_evidence)) if (evalLeaf(l, facts) !== T) { const id = l.field.split(".")[1]; res.missing_evidence.add(id); }
      res.reasons.push({ code: `${p.policy_id}:EVIDENCE`, detail: "required evidence not PRESENT" });
    }
    if (evalPred(p.required_targets, facts) !== T) {
      res.failing.add("NEEDS_TARGET");
      for (const l of collectLeaves(p.required_targets)) if (evalLeaf(l, facts) !== T) res.missing_targets.add(l.field.split(".")[1]);
      res.reasons.push({ code: `${p.policy_id}:TARGET`, detail: "target identity/scope not validated" });
    }
    if (evalPred(p.authority_requirements, facts) !== T) { res.failing.add("NEEDS_AUTHORIZATION"); res.reasons.push({ code: `${p.policy_id}:AUTHORITY`, detail: "authority requirement not granted" }); }
    for (const c of p.criticality_constraints ?? []) {
      if (evalPred(c.when, facts) !== T) continue;
      if (c.effect === "USE_VARIANT") { res.variant = c.variant; res.flags.add("VARIANT_SELECTED"); }
      if (c.effect === "REQUIRE_AUTHORITY" && facts.authority.get(c.authority) !== true) { res.failing.add("NEEDS_AUTHORIZATION"); res.reasons.push({ code: `${p.policy_id}:CRIT_AUTH`, detail: `${c.authority} approval required for this criticality` }); }
      if (c.effect === "PROHIBIT") { res.failing.add("PROHIBITED"); res.reasons.push({ code: `${p.policy_id}:CRIT_PROHIBIT`, detail: c.reason ?? "prohibited by criticality" }); }
    }
    if ((p.tool_capability_any_of ?? []).length) {
      const vals = p.tool_capability_any_of.map((c) => facts.capability.get(c));
      const anyOk = vals.some((v) => v === true || (v === undefined && mode !== "strict"));
      if (!anyOk) { res.failing.add("UNSUPPORTED"); res.reasons.push({ code: `${p.policy_id}:CAP_ANY`, detail: "none of the alternative capabilities is supported" }); }
      else if (vals.some((v) => v === undefined)) res.flags.add("TOOL_MAPPING_REQUIRED");
    }
    for (const cap of p.tool_capability_requirements ?? []) {
      const v = facts.capability.get(cap);
      if (v === false || (v === undefined && mode === "strict")) { res.failing.add("UNSUPPORTED"); res.reasons.push({ code: `${p.policy_id}:CAP`, detail: `${cap} not supported` }); }
      else if (v === undefined) res.flags.add("TOOL_MAPPING_REQUIRED");
    }
  }
  return finish(res);
}
function finish(res) {
  res.decision = FAIL_RANK.find((r) => res.failing.has(r)) ?? "ELIGIBLE";
  res.missing_evidence = [...res.missing_evidence]; res.missing_targets = [...res.missing_targets]; res.flags = [...res.flags];
  return res;
}

export function evaluateBranchGate(kb, gateId, originSubtype, facts) {
  const p = kb.policies.get(gateId);
  if (!p) return { ok: false, reason: "missing gate" };
  if (!p.applicable_subtypes.includes(originSubtype)) return { ok: false, reason: "gate not applicable to origin" };
  for (const pr of p.prohibitions ?? []) if (evalPred(pr.when, facts) === T) return { ok: false, reason: pr.id };
  return { ok: evalPred(p.required_evidence, facts) === T, reason: "required_evidence" };
}

// ---------------------------------------------------------------- planner -------------------------------------------
const STAGE_RANK = { STOP_ACTIVE: 0, CLOSE_PATH: 1, IDENTITY_EXPOSURE: 2, CLEANUP_OBJECT: 3, NONE: 9 };

export function planIncident(kb, rawFacts, mode = "platform_neutral") {
  const facts = normalizeFacts(rawFacts, { ir_execute: kb.orgContext.authority_defaults?.ir_execute?.granted ?? true });
  const eff = new Map();
  for (const pb of kb.playbooks.values()) if (evalPred(pb.classification_evidence, facts) === T) eff.set(pb.subtype_id, pb);
  const origin = new Set(eff.keys());
  const queue = [...eff.values()];
  const opened = [];
  while (queue.length) {
    const pb = queue.shift();
    for (const br of pb.related_branches ?? []) {
      if (eff.has(br.subtype_id) || evalPred(br.open_when, facts) !== T) continue;
      if (br.gate_policy && !evaluateBranchGate(kb, br.gate_policy, pb.subtype_id, facts).ok) continue;
      const next = kb.playbooks.get(br.subtype_id); if (!next) continue;
      eff.set(br.subtype_id, next); opened.push(`${pb.subtype_id}->${br.subtype_id}`); queue.push(next);
    }
  }
  const effective = [...eff.values()];
  const vetoed = [];
  const nodes = new Map();
  let order = 0;
  for (const pb of effective) {
    const scenarios = pb.scenarios.filter((s) => evalPred(s.when, facts) === T);
    for (const sc of scenarios) for (const ref of sc.ordered_action_refs) {
      const extra = ref.condition && ref.condition !== "POLICY_ELIGIBLE" ? evalPred(ref.condition, facts) : T;
      const dec = evaluateAction(kb, ref.action_id, pb.subtype_id, facts, mode);
      if (extra !== T && dec.decision === "ELIGIBLE") { dec.decision = "NEEDS_EVIDENCE"; dec.reasons.push({ code: "SCENARIO_CONDITION", detail: "scenario-specific condition not TRUE" }); }
      const prev = nodes.get(ref.action_id);
      if (!prev) nodes.set(ref.action_id, { action_id: ref.action_id, decision: dec, subtype: pb.subtype_id, scenario: sc.scenario_id, depends_on: new Set(ref.depends_on ?? []), reason: ref.order_reason, fallback: ref.fallback_action, idx: order++ });
      else { // same action reached from another branch: eligible if any context eligible; union dependencies
        for (const d of ref.depends_on ?? []) prev.depends_on.add(d);
        if (prev.decision.decision !== "ELIGIBLE" && dec.decision === "ELIGIBLE") { prev.decision = dec; prev.subtype = pb.subtype_id; prev.scenario = sc.scenario_id; }
      }
    }
  }
  const eligible = [...nodes.values()].filter((n) => n.decision.decision === "ELIGIBLE");
  const notEligible = [...nodes.values()].filter((n) => n.decision.decision !== "ELIGIBLE");
  // ordering: Kahn with (stage rank, insertion) priority; dependencies on non-included actions are ignored
  const inc = new Map(eligible.map((n) => [n.action_id, n]));
  const indeg = new Map(eligible.map((n) => [n.action_id, [...n.depends_on].filter((d) => inc.has(d)).length]));
  const ordered = [], ready = eligible.filter((n) => indeg.get(n.action_id) === 0);
  const stage = (n) => STAGE_RANK[kb.actions.get(n.action_id)?.containment_stage] ?? 9;
  while (ready.length) {
    // deterministic: containment stage first, then action_id (never file/insertion order)
    ready.sort((a, b) => stage(a) - stage(b) || a.action_id.localeCompare(b.action_id));
    const n = ready.shift(); ordered.push(n);
    for (const m of eligible) if (m.depends_on.has(n.action_id) && inc.has(n.action_id)) { indeg.set(m.action_id, indeg.get(m.action_id) - 1); if (indeg.get(m.action_id) === 0) ready.push(m); }
  }
  const cyc = eligible.length !== ordered.length;
  if (!ordered.some((n) => kb.actions.get(n.action_id)?.phase === "CONTAINMENT")) {
    const dec = evaluateAction(kb, "ACT-INVESTIGATE-MISSING-EVIDENCE", "*", facts, mode);
    const gaps = notEligible.flatMap((n) => [n.decision.missing_evidence, n.decision.missing_targets]).flat();
    if (!nodes.has("ACT-INVESTIGATE-MISSING-EVIDENCE")) { const nd = { action_id: "ACT-INVESTIGATE-MISSING-EVIDENCE", decision: dec, subtype: "*", scenario: "SC-FALLBACK-INVESTIGATION", depends_on: new Set(), reason: "ไม่มี containment action ที่ผ่านเงื่อนไข", idx: order++, gaps }; nodes.set(nd.action_id, nd); ordered.push(nd); }
  }
  return { facts, active: effective.map((p) => p.subtype_id), opened, vetoed, ordered, notEligible, cyclic: cyc, nodes };
}

// ---------------------------------------------------------------- step selection ------------------------------------
const PH = /\{\{\s*([a-z_]+)\.([a-z_]+)\s*\}\}/g;
export function placeholdersOf(text) { const out = []; let m; PH.lastIndex = 0; while ((m = PH.exec(text))) out.push({ type: m[1], field: m[2] }); return out; }

export function selectSteps(kb, runbookId, facts, variant, depth = 0, eligible = new Set()) {
  const rb = kb.runbooks.get(runbookId);
  const out = { included: [], omitted: [] };
  if (!rb || depth > 3) return out;
  for (const st of rb.ordered_steps) {
    if (st.variant && st.variant !== (variant ?? "standard")) continue;
    if ((st.skip_if_eligible ?? []).some((a) => eligible.has(a))) continue;
    const cond = evalPred(st.condition, facts);
    const missingTypes = placeholdersOf(st.instruction ?? "").filter((p) => p.type !== "missing" && (!facts.targets.has(p.type) || facts.fieldsMissing.has(`${p.type}.${p.field}`))).map((p) => p.type);
    if (cond !== T || missingTypes.length) { out.omitted.push({ runbook: runbookId, step: st.step_id, def: st, missing_targets: [...new Set(missingTypes)], condition: cond }); continue; }
    if (st.include_runbook) { const sub = selectSteps(kb, st.include_runbook, facts, variant, depth + 1, eligible); out.included.push(...sub.included); out.omitted.push(...sub.omitted); continue; }
    out.included.push({ runbook: runbookId, step: st.step_id, fold: !!st.fold, def: st });
  }
  return out;
}
