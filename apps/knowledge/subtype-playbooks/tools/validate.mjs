// validate.mjs — reference integrity + coverage + validation-case runner.   usage: node validate.mjs [--write-matrix]
import fs from "node:fs";
import path from "node:path";
import { loadAll, ROOT, collectLeaves, placeholdersOf, planIncident, selectSteps } from "./lib.mjs";
import { buildChunks, checkChunkInvariant } from "./build-chunks.mjs";

const kb = loadAll();
const errors = [], warns = [];
const err = (m) => errors.push(m), warn = (m) => warns.push(m);
const OPS = new Set(Object.keys(kb.dictionary.operators));
const CAPS = new Set(Object.keys(kb.dictionary.capabilities));
const AUTH = new Set(Object.keys(kb.dictionary.authorities));
const REVIEW = new Set(["DRAFT", "IR_REVIEW_PENDING", "IR_REVIEWED"]);
const ORIGINS = new Set(["EXPANDED_FROM_REFERENCE", "DERIVED_ADDITION", "REFERENCE"]);
const SCOPE = new Set(Object.keys(kb.dictionary.scope_flags));
const CTX = new Set(Object.keys(kb.dictionary.namespaces.context.fields));
const TT = kb.targetTypes;
const STAGES = new Set(["STOP_ACTIVE", "CLOSE_PATH", "IDENTITY_EXPOSURE", "CLEANUP_OBJECT", "NONE"]);

// ---- duplicates
for (const d of kb.dup) err(`duplicate id: ${d}`);

// ---- target types
for (const [id, t] of Object.entries(TT)) {
  if (!t.required_identity_fields?.length) err(`target ${id}: no required_identity_fields`);
  if (!t.validation_rules?.length) err(`target ${id}: no validation_rules`);
}

// ---- predicate field validation
function checkPred(pred, where) {
  for (const leaf of collectLeaves(pred)) {
    const f = leaf.field, p = f.split(".");
    if (!OPS.has(leaf.operator)) err(`${where}: bad operator ${leaf.operator}`);
    if (leaf.value === undefined) err(`${where}: leaf ${f} has no value`);
    switch (p[0]) {
      case "evidence":
        if (!kb.evidence.has(p[1])) err(`${where}: unknown evidence '${p[1]}' in ${f}`);
        if (!["status", "authorization_status"].includes(p[2])) err(`${where}: bad evidence attribute in ${f}`);
        break;
      case "targets": if (!TT[p[1]] || p[2] !== "validated" || p.length !== 3) err(`${where}: bad target field ${f}`); break;
      case "scope": if (!SCOPE.has(f)) err(`${where}: undefined scope flag ${f}`); break;
      case "authority": if (!AUTH.has(p[1]) || p[2] !== "granted") err(`${where}: bad authority field ${f}`); break;
      case "capability": { const id = p.slice(1, -1).join("."); if (!CAPS.has(id) || p.at(-1) !== "supported") err(`${where}: bad capability field ${f}`); break; }
      case "context": if (!CTX.has(f)) err(`${where}: undefined context field ${f}`); break;
      default: err(`${where}: field outside dictionary: ${f}`);
    }
  }
}

// ---- families: actions / policies / playbooks / runbooks
for (const a of kb.actions.values()) {
  const w = `action ${a.action_id}`;
  if (!STAGES.has(a.containment_stage)) err(`${w}: bad containment_stage`);
  for (const t of a.supported_target_types ?? []) if (!TT[t]) err(`${w}: unknown target type ${t}`);
  for (const t of a.target_requirements ?? []) if (!TT[t]) err(`${w}: unknown target_requirement ${t}`);
  for (const e of a.evidence_requirements ?? []) if (!kb.evidence.has(e)) err(`${w}: unknown evidence ${e}`);
  if (!a.runbook_refs?.length) err(`${w}: no runbook`);
  if (!/[฀-๿]/.test(a.label_th ?? "")) err(`${w}: label_th (Thai label shown to users) is missing`);
  if (!["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(a.impact_level)) err(`${w}: impact_level must be LOW|MEDIUM|HIGH|CRITICAL`);
  if (!REVIEW.has(a.review_status)) err(`${w}: review_status must be one of ${[...REVIEW].join("|")}`);
  for (const r of a.runbook_refs ?? []) {
    const rb = kb.runbooks.get(r);
    if (!rb) err(`${w}: runbook ${r} missing`); else if (!rb.supported_action_ids.includes(a.action_id)) err(`${w}: runbook ${r} does not list the action`);
  }
  if (a.action_id !== "ACT-INVESTIGATE-MISSING-EVIDENCE" && a.phase === "CONTAINMENT" && !(a.execution_constraints?.length)) warn(`${w}: no execution_constraints`);
  const gates = [...kb.policies.values()].filter((p) => p.rule_type === "ACTION_GATE" && p.action_id === a.action_id);
  if (!gates.length) err(`${w}: no ACTION_GATE policy`);
  for (const g of gates) {
    for (const l of collectLeaves(g.required_evidence)) { const id = l.field.split(".")[1]; if (l.field.startsWith("evidence.") && !a.evidence_requirements.includes(id)) err(`${w}: policy ${g.policy_id} uses evidence ${id} not listed in action.evidence_requirements`); }
    for (const l of collectLeaves(g.required_targets)) { const t = l.field.split(".")[1]; if (l.field.startsWith("targets.") && !a.target_requirements.includes(t)) err(`${w}: policy ${g.policy_id} requires target ${t} not in action.target_requirements`); }
  }
}
for (const r of kb.runbooks.values()) {
  const w = `runbook ${r.runbook_id}`;
  for (const aid of r.supported_action_ids) { const a = kb.actions.get(aid); if (!a) err(`${w}: unknown action ${aid}`); else if (!a.runbook_refs.includes(r.runbook_id)) err(`${w}: action ${aid} does not reference it`); }
  for (const s of r.supported_subtypes) if (s !== "*" && !kb.playbooks.has(s)) err(`${w}: unknown subtype ${s}`);
  for (const c of r.required_capabilities ?? []) if (!CAPS.has(c)) err(`${w}: unknown capability ${c}`);
  for (const a of r.required_authority ?? []) if (!AUTH.has(a) && a !== "ir_execute") err(`${w}: unknown authority ${a}`);
  for (const e of r.required_evidence ?? []) if (!kb.evidence.has(e)) err(`${w}: unknown evidence ${e}`);
  for (const t of r.required_targets ?? []) if (!TT[t]) err(`${w}: unknown target ${t}`);
  if (!r.tool_variants?.some((v) => v.tool === "TOOL_MAPPING_REQUIRED")) err(`${w}: tool_variants must declare TOOL_MAPPING_REQUIRED while org mapping is MISSING`);
  if (!r.ordered_steps?.length) err(`${w}: no steps`);
  if (!r.verification?.length) err(`${w}: no verification`);
  if (!r.failure_handling?.length) err(`${w}: no failure_handling`);
  const ids = new Set(); const vset = new Set(["standard", ...(r.variants ?? []).map((v) => v.variant_id)]);
  let real = 0;
  for (const s of r.ordered_steps) {
    const sw = `${w}/${s.step_id}`;
    if (ids.has(s.step_id)) err(`${sw}: duplicate step id`); ids.add(s.step_id);
    for (const k of ["instruction", "expected_result", "verify", "on_failure"]) if (!s[k]) err(`${sw}: missing ${k}`);
    // folded pre-checks, verify-only steps (rendered as 'ตรวจผล') and include_runbook steps have no title of their own
    const needsTitle = !s.fold && !s.include_runbook && s.kind !== "verify" && !/^ตรวจ/.test(s.instruction ?? "");
    if (needsTitle && !/[฀-๿]/.test(s.title ?? "")) err(`${sw}: explicit Thai title is missing`);
    if (s.kind && !["action", "verify"].includes(s.kind)) err(`${sw}: kind must be action|verify`);
    if (!ORIGINS.has(s.origin)) err(`${sw}: origin must be one of ${[...ORIGINS].join("|")}`);
    if (s.operation && !["terminate_process", "terminate_children"].includes(s.operation)) err(`${sw}: unknown operation ${s.operation}`);
    if (s.operation && !s.operates_on) err(`${sw}: operation ${s.operation} requires operates_on (target binding)`);
    for (const sk of s.skip_if_eligible ?? []) if (!kb.actions.has(sk)) err(`${sw}: skip_if_eligible unknown action ${sk}`);
    if (s.include_runbook && !kb.runbooks.has(s.include_runbook)) err(`${sw}: include_runbook ${s.include_runbook} missing`);
    if (s.variant && !vset.has(s.variant)) err(`${sw}: variant ${s.variant} not declared`);
    if (s.manual_owner && !AUTH.has(s.manual_owner)) err(`${sw}: manual_owner ${s.manual_owner} unknown`);
    if (s.include_runbook) { const inc = kb.runbooks.get(s.include_runbook); const condT = new Set(collectLeaves(s.condition).filter((l) => l.field.startsWith("targets.")).map((l) => l.field.split(".")[1])); for (const t of inc?.required_targets ?? []) if (!(r.required_targets ?? []).includes(t) && !condT.has(t)) err(`${sw}: include_runbook ${s.include_runbook} needs target ${t} guarded by condition`); }
    if (!s.fold) real++;
    if (/ดำเนินการตาม\s*RB-/.test(s.instruction ?? "")) err(`${sw}: instruction ends in 'follow RB-…' (forbidden)`);
    checkPred(s.condition, sw);
    const condTypes = new Set(collectLeaves(s.condition).filter((l) => l.field.startsWith("targets.")).map((l) => l.field.split(".")[1]));
    // every user-visible text field must only use placeholders that resolve to a defined, guarded target field
    // ---- requirements by step KIND (folded pre-checks, verify-only and include_runbook steps are not forced into the operational schema)
    {
      const kind = s.include_runbook ? "include" : s.fold ? "fold" : (s.kind === "verify" || /^ตรวจ/.test(s.instruction ?? "")) ? "verify" : "operational";
      const BASES = new Set(["EXISTING", "NEUTRAL_DERIVED", "ORG_INPUT_REQUIRED", "IR_REVIEW_REQUIRED"]);
      if (kind === "operational") {
        if (!BASES.has(s.method_basis)) err(`${sw}: operational step needs method_basis (${[...BASES].join("|")})`);
        else if (s.method_basis === "ORG_INPUT_REQUIRED" || s.method_basis === "IR_REVIEW_REQUIRED") {
          if (!s.method_requires) err(`${sw}: ${s.method_basis} step must state method_requires (what the organization/IR must supply)`);
          if (s.method) err(`${sw}: ${s.method_basis} step must not carry a method (it is not ready until the missing information exists)`);
        } else {
          if (!s.method) err(`${sw}: ${s.method_basis} step needs a method`);
          else {
            // a method must say HOW beyond restating the instruction: it has to contain a check / record / hand-off element, and not be the instruction itself
            if (s.method.trim() === (s.instruction ?? "").trim()) err(`${sw}: method only repeats the instruction`);
            if (!/(ตรวจ|บันทึก|ขออนุมัติ|แจ้ง|ทดสอบ|ยืนยัน|ค้นหา|เทียบ|ส่ง)/.test(s.method)) err(`${sw}: method gives no check/record/hand-off - it is still a broad instruction`);
            if (/(\bAPI\b|เมนู|คลิก|https?:\/\/|\bcurl\b|\bkubectl\b|PowerShell\s+cmdlet)/i.test(s.method)) err(`${sw}: method names a menu/API/command that no knowledge supports`);
          }
          if (!/\{\{[a-z_]+\.[a-z_]+\}\}/.test(`${s.title ?? ""} ${s.method ?? ""} ${s.instruction ?? ""}`) && !s.manual_owner) err(`${sw}: operational step names no target/scope placeholder`);
        }
        if (!(r.prerequisites ?? []).length) err(`${w}: operational runbook has no prerequisites`);
        if (!(r.required_authority ?? []).length) err(`${w}: operational runbook states no authority requirement`);
        if (!s.verify) err(`${sw}: operational step has no verification`);
      } else if (s.method_basis || s.method_requires) err(`${sw}: ${kind} step must not carry method_basis/method_requires`);
      for (const k of s.requires_org ?? []) if (!["approved_access"].includes(k)) err(`${sw}: unknown requires_org '${k}'`);
      const order = r.ordered_steps.map((x) => x.step_id);
      for (const pid of s.needs_prior ?? []) if (!order.includes(pid) || order.indexOf(pid) >= order.indexOf(s.step_id)) err(`${sw}: needs_prior '${pid}' must be an earlier step of the same runbook`);
    }
    if (s.requires_confirmed_tool) {
      if (!s.method) err(`${sw}: requires_confirmed_tool step must state its 'method' (how the action is performed, identifying the flow/session)`);
      if (!collectLeaves(s.condition).some((l) => /^capability\.cap\.[a-z_]+\.supported$/.test(l.field))) err(`${sw}: requires_confirmed_tool step must be guarded by a capability condition`);
      if (/หาก\s*control\s*รองรับ/.test(`${s.instruction} ${s.method ?? ""}`)) err(`${sw}: 'if the control supports it' is a condition, not an instruction`);
    }
    for (const ph of [s.instruction, s.title, s.method, s.impact, s.verify, s.expected_result, s.rollback, s.on_failure].flatMap((t) => placeholdersOf(t ?? ""))) {
      if (ph.type === "missing") continue;
      const t = TT[ph.type];
      if (!t) { err(`${sw}: placeholder {{${ph.type}.${ph.field}}} unknown target type`); continue; }
      if (![...t.required_identity_fields, ...(t.optional_fields ?? [])].includes(ph.field)) err(`${sw}: placeholder field ${ph.type}.${ph.field} not defined in target-types`);
      if (!(r.required_targets ?? []).includes(ph.type) && !condTypes.has(ph.type)) err(`${sw}: placeholder target '${ph.type}' is neither a runbook required_target nor guarded by step.condition`);
    }
    if (/\{\{(?![a-z_]+\.[a-z_]+\}\})/.test(s.instruction ?? "")) err(`${sw}: malformed placeholder`);
  }
  if (!real) err(`${w}: only fold steps`);
}
for (const p of kb.policies.values()) {
  const w = `policy ${p.policy_id}`;
  if (!p.covers) err(`${w}: no covers[]`);
  if (!p.reason) err(`${w}: no reason`);
  if (p.rule_type === "ACTION_GATE") {
    if (!kb.actions.has(p.action_id)) err(`${w}: unknown action ${p.action_id}`);
    for (const s of p.applicable_subtypes) if (s !== "*" && !kb.playbooks.has(s)) err(`${w}: unknown subtype ${s}`);
    checkPred(p.required_evidence, w + "/evidence"); checkPred(p.required_targets, w + "/targets"); checkPred(p.authority_requirements, w + "/authority");
    for (const x of p.prohibitions ?? []) { if (!x.id || !x.reason) err(`${w}: prohibition missing id/reason`); checkPred(x.when, `${w}/${x.id}`); }
    for (const c of p.criticality_constraints ?? []) { checkPred(c.when, w + "/criticality"); if (c.effect === "USE_VARIANT") { const rbs = (kb.actions.get(p.action_id)?.runbook_refs ?? []).map((r) => kb.runbooks.get(r)); if (!rbs.some((r) => (r?.variants ?? []).some((v) => v.variant_id === c.variant))) err(`${w}: variant ${c.variant} not declared in the action's runbook`); } if (c.effect === "REQUIRE_AUTHORITY" && !AUTH.has(c.authority)) err(`${w}: unknown authority ${c.authority}`); }
    for (const e of p.authorization_gate ?? []) { if (!kb.evidence.has(e)) err(`${w}: authorization_gate unknown evidence ${e}`); else if (!kb.evidence.get(e).may_be_authorized) err(`${w}: authorization_gate on evidence ${e} which cannot be authorized`); }
    for (const c of p.tool_capability_requirements ?? []) {
      if (!CAPS.has(c)) err(`${w}: unknown capability ${c}`);
      const rbs = (kb.actions.get(p.action_id)?.runbook_refs ?? []).map((r) => kb.runbooks.get(r));
      if (!rbs.some((r) => (r?.required_capabilities ?? []).includes(c))) err(`${w}: capability ${c} is not in the action's runbook required_capabilities`);
    }
    if (p.fallback && !kb.actions.has(p.fallback.action_id)) err(`${w}: fallback action missing`);
    for (const c of p.tool_capability_any_of ?? []) { if (!CAPS.has(c)) err(`${w}: unknown capability ${c}`); const rbs = (kb.actions.get(p.action_id)?.runbook_refs ?? []).map((r) => kb.runbooks.get(r)); if (!rbs.some((r) => (r?.required_capabilities ?? []).includes(c))) err(`${w}: capability ${c} is not in the action's runbook required_capabilities`); }
    if (!p.fallback && p.action_id !== "ACT-INVESTIGATE-MISSING-EVIDENCE") warn(`${w}: no fallback`);
  } else if (p.rule_type === "BRANCH_GATE") {
    for (const b of p.branch_subtypes ?? [p.branch_subtype]) if (!kb.playbooks.has(b)) err(`${w}: unknown branch subtype ${b}`);
    checkPred(p.required_evidence, w); for (const x of p.prohibitions ?? []) checkPred(x.when, `${w}/${x.id}`);
  } else if (p.rule_type === "GLOBAL_PROHIBITION") {
    for (const x of p.prohibitions ?? []) checkPred(x.when, `${w}/${x.id}`);
  } else if (!["OUTPUT_CONSTRAINT", "CLASSIFICATION_RULE"].includes(p.rule_type)) err(`${w}: bad rule_type`);
}
for (const pb of kb.playbooks.values()) {
  const w = `playbook ${pb.playbook_id}`;
  const reg = kb.registry.families[pb.attack_family]?.subtypes.find((s) => s.id === pb.subtype_id);
  if (!reg) err(`${w}: subtype ${pb.subtype_id} not in reference registry`);
  checkPred(pb.classification_evidence, w);
  if (!pb.insufficient_evidence?.length) err(`${w}: no insufficient_evidence`);
  if (!pb.stop_escalation?.length) err(`${w}: no stop_escalation`);
  if (!pb.scenarios?.length) err(`${w}: no scenarios`);
  for (const pr of pb.policy_refs ?? []) if (!kb.policies.has(pr)) err(`${w}: policy_ref ${pr} missing`);
  for (const se of pb.stop_escalation ?? []) checkPred(se.when, w + "/stop");
  for (const br of pb.related_branches ?? []) { if (!kb.playbooks.has(br.subtype_id)) err(`${w}: related branch ${br.subtype_id} missing`); checkPred(br.open_when, w + "/branch"); if (br.gate_policy && !kb.policies.has(br.gate_policy)) err(`${w}: gate_policy ${br.gate_policy} missing`); }
  for (const sc of pb.scenarios ?? []) {
    checkPred(sc.when, `${w}/${sc.scenario_id}`);
    const ids = new Set(sc.ordered_action_refs.map((r) => r.action_id));
    for (const ref of sc.ordered_action_refs) {
      if (!kb.actions.has(ref.action_id)) err(`${w}/${sc.scenario_id}: unknown action ${ref.action_id}`);
      if (ref.condition !== "POLICY_ELIGIBLE") checkPred(ref.condition, `${w}/${sc.scenario_id}`);
      for (const d of ref.depends_on ?? []) if (!ids.has(d)) err(`${w}/${sc.scenario_id}: depends_on ${d} not in scenario`);
      if (ref.fallback_action && !kb.actions.has(ref.fallback_action)) err(`${w}: fallback_action ${ref.fallback_action} missing`);
      if (!ref.order_reason) err(`${w}/${sc.scenario_id}: ${ref.action_id} missing order_reason`);
      const a = kb.actions.get(ref.action_id);
      if (a && !a.phase) err(`${w}: action ${ref.action_id} no phase`);
      // policy must exist for this subtype
      const ok = [...kb.policies.values()].some((p) => p.rule_type === "ACTION_GATE" && p.action_id === ref.action_id && (p.applicable_subtypes.includes("*") || p.applicable_subtypes.includes(pb.subtype_id)));
      if (!ok) err(`${w}/${sc.scenario_id}: no policy for ${ref.action_id} in subtype ${pb.subtype_id}`);
    }
    // cycle detection
    const color = new Map();
    const dfs = (n) => { color.set(n, 1); for (const d of sc.ordered_action_refs.find((r) => r.action_id === n)?.depends_on ?? []) { if (color.get(d) === 1) err(`${w}/${sc.scenario_id}: cyclic dependency at ${d}`); else if (!color.get(d)) dfs(d); } color.set(n, 2); };
    for (const id of ids) if (!color.get(id)) dfs(id);
  }
}

// ---- structural policy assertions
for (const p of kb.policies.values()) if ((p.covers ?? []).includes("MAL-P5")) { const t = collectLeaves(p.required_targets).map((l) => l.field); if (t.some((f) => f.startsWith("targets.file_object"))) err(`policy ${p.policy_id} covers MAL-P5 but requires a file_object target`); }
for (const r of kb.runbooks.values()) for (const s of r.ordered_steps) if (/\{\{business_item\./.test(s.instruction ?? "") && !s.manual_owner) err(`runbook ${r.runbook_id}/${s.step_id}: business_item step must be MANUAL with manual_owner (PH-P4)`);

for (const r of kb.runbooks.values()) if (r.supported_subtypes.some((x) => x.startsWith("SQ-")) && !(r.remediation_followups ?? []).length) err(`runbook ${r.runbook_id}: SQL injection runbook must list remediation_followups separately from containment (SQ-P6)`);

// ---- registry coverage (reference -> knowledge)
const matrix = [];
for (const [fam, def] of Object.entries(kb.registry.families)) {
  for (const s of def.subtypes) {
    const pb = kb.playbooks.get(s.id);
    const row = { family: fam, subtype: s.id, name: s.name, runbook: s.runbook, playbook: !!pb, action: "", policy: "", classification: false, branches: 0 };
    if (!pb) { err(`coverage: subtype ${s.id} has no playbook`); matrix.push(row); continue; }
    if (pb.attack_family !== fam) err(`coverage: ${s.id} playbook family ${pb.attack_family} != ${fam}`);
    if (pb.subtype_name !== s.name) warn(`coverage: ${s.id} subtype_name '${pb.subtype_name}' differs from reference '${s.name}'`);
    const rb = kb.runbooks.get(s.runbook);
    if (!rb) err(`coverage: runbook ${s.runbook} (${s.id}) missing`);
    else if (!rb.supported_subtypes.includes(s.id)) err(`coverage: ${s.runbook} supported_subtypes lacks ${s.id}`);
    const act = rb && rb.supported_action_ids[0];
    row.action = act ?? "";
    const inPb = pb.scenarios.some((sc) => sc.ordered_action_refs.some((r) => r.action_id === act));
    if (!inPb) err(`coverage: playbook ${pb.playbook_id} does not order action ${act}`);
    const gates = [...kb.policies.values()].filter((p) => p.rule_type === "ACTION_GATE" && p.action_id === act && p.applicable_subtypes.includes(s.id));
    row.policy = gates.map((g) => g.policy_id).join(",");
    if (!gates.length) err(`coverage: no ACTION_GATE for ${act} in ${s.id}`);
    row.classification = true; row.branches = (pb.related_branches ?? []).length;
    matrix.push(row);
  }
}
const covered = new Set([...kb.policies.values()].flatMap((p) => p.covers ?? []));
const uncovered = [];
for (const [fam, def] of Object.entries(kb.registry.families)) for (const it of def.policy_items) if (!covered.has(it.id)) { err(`policy item ${it.id} not covered by any rule: ${it.text}`); uncovered.push(it.id); }
for (const g of kb.registry.global_principles) if (!covered.has(g.id)) { err(`global principle ${g.id} not covered by any rule`); uncovered.push(g.id); }
for (const c of covered) { const known = kb.registry.global_principles.some((g) => g.id === c) || Object.values(kb.registry.families).some((f) => f.policy_items.some((i) => i.id === c) || f.subtypes.some((s) => s.id === c)); if (!known) warn(`covers: unknown reference id ${c}`); }
// every reference RB id appears
for (const [fam, def] of Object.entries(kb.registry.families)) for (const s of def.subtypes) if (!kb.runbooks.has(s.runbook)) err(`reference RB ${s.runbook} missing`);
// every action has runbook+policy (checked), every runbook used
for (const r of kb.runbooks.values()) if (!r.supported_action_ids.length) err(`runbook ${r.runbook_id} unused`);

// ---- policy self-tests: every ACTION_GATE can reach ELIGIBLE, and EVERY prohibition rule (incl. global ones) demonstrably flips it to PROHIBITED
import { evaluateAction, normalizeFacts } from "./lib.mjs";
function synthesize(g) {
  const raw = { evidence: {}, targets: [], scope: [], authority: [], context: {} };
  const setEv = (id, k, v) => { const [st = "PRESENT", au = "UNAUTHORIZED"] = (raw.evidence[id] ?? "PRESENT/UNAUTHORIZED").split("/"); raw.evidence[id] = k === "status" ? `${v}/${au}` : `${st}/${v}`; };
  const pick = (pred, setter) => { if (!pred) return; if (pred.field) return setter(pred); const k = ["all_of", "any_of"].find((x) => pred[x]); if (!k) return; if (k === "any_of") pick(pred.any_of[0], setter); else pred.all_of.forEach((q) => pick(q, setter)); };
  const apply = (l) => {
    const f = l.field.split(".");
    if (f[0] === "evidence") setEv(f[1], f[2], l.value);
    else if (f[0] === "targets") raw.targets.push(f[1]);
    else if (f[0] === "scope") raw.scope.push(l.field.replace("scope.", ""));
    else if (f[0] === "authority") raw.authority.push(f[1]);
    else if (f[0] === "context") raw.context[l.field] = Array.isArray(l.value) ? l.value[0] : l.value;
  };
  pick(g.required_evidence, apply); pick(g.required_targets, apply); pick(g.authority_requirements, apply);
  for (const e of g.authorization_gate ?? []) setEv(e, "authorization_status", "UNAUTHORIZED"), setEv(e, "status", "PRESENT");
  return raw;
}
let selfTests = 0;
const clone = (o) => JSON.parse(JSON.stringify(o));
const applyWhen = (raw, w) => { const l = collectLeaves(w)[0]; const f = l.field.split("."); if (f[0] === "scope") raw.scope.push(f[1]); else if (f[0] === "evidence") { const [st, au] = (raw.evidence[f[1]] ?? "PRESENT/UNAUTHORIZED").split("/"); raw.evidence[f[1]] = f[2] === "status" ? `${l.value}/${au}` : `${st}/${l.value}`; } else if (f[0] === "context") raw.context[l.field] = Array.isArray(l.value) ? l.value[0] : l.value; };
const globalProh = [...kb.policies.values()].filter((p) => p.rule_type === "GLOBAL_PROHIBITION").flatMap((p) => p.prohibitions);
for (const g of kb.policies.values()) {
  if (g.rule_type !== "ACTION_GATE" || g.action_id === "ACT-INVESTIGATE-MISSING-EVIDENCE" && !(g.prohibitions ?? []).length) continue;
  const subtype = g.applicable_subtypes.includes("*") ? "PS-PERSIST" : g.applicable_subtypes[0];
  const base = synthesize(g);
  const r0 = evaluateAction(kb, g.action_id, subtype, normalizeFacts(base));
  selfTests++;
  if (r0.decision !== "ELIGIBLE") { err(`self-test ${g.policy_id}: synthesized facts do not reach ELIGIBLE (got ${r0.decision}: ${r0.reasons.map((x) => x.code)})`); continue; }
  for (const pr of [...(g.prohibitions ?? []), ...(g.action_id === "ACT-AUTH-SOURCE-RESTRICT" ? globalProh : [])]) {
    const raw = clone(base); applyWhen(raw, pr.when);
    const r = evaluateAction(kb, g.action_id, subtype, normalizeFacts(raw)); selfTests++;
    if (r.decision !== "PROHIBITED" || !r.reasons.some((x) => x.code === pr.id)) err(`self-test ${g.policy_id}/${pr.id}: prohibition did not fire (got ${r.decision})`);
  }
  // each authorization_gate evidence flips to PROHIBITED when AUTHORIZED, NEEDS_EVIDENCE when UNKNOWN
  for (const e of g.authorization_gate ?? []) {
    const a = clone(base); a.evidence[e] = "PRESENT/AUTHORIZED"; const ra = evaluateAction(kb, g.action_id, subtype, normalizeFacts(a)); selfTests++;
    if (ra.decision !== "PROHIBITED") err(`self-test ${g.policy_id}: AUTHORIZED ${e} did not prohibit (got ${ra.decision})`);
    const u = clone(base); u.evidence[e] = "PRESENT/UNKNOWN"; const ru = evaluateAction(kb, g.action_id, subtype, normalizeFacts(u)); selfTests++;
    if (ru.decision !== "NEEDS_EVIDENCE") err(`self-test ${g.policy_id}: UNKNOWN authorization of ${e} did not give NEEDS_EVIDENCE (got ${ru.decision})`);
  }
  // removing each required target / evidence / authority downgrades the decision (never stays ELIGIBLE)
  for (const t of base.targets) { const m = clone(base); m.targets = m.targets.filter((x) => x !== t); if (collectLeaves(g.required_targets).length > 1 && JSON.stringify(g.required_targets).includes("any_of")) continue; const rm = evaluateAction(kb, g.action_id, subtype, normalizeFacts(m)); selfTests++; if (rm.decision === "ELIGIBLE") err(`self-test ${g.policy_id}: removing target ${t} still ELIGIBLE`); }
  for (const a of base.authority) { const m = clone(base); m.authority = m.authority.filter((x) => x !== a); const rm = evaluateAction(kb, g.action_id, subtype, normalizeFacts(m)); selfTests++; if (rm.decision === "ELIGIBLE") err(`self-test ${g.policy_id}: removing authority ${a} still ELIGIBLE`); }
}

// ---- per-subtype plan smoke tests (generated): classification+gate facts => subtype active + primary action ELIGIBLE and ordered; classification-only => no containment, investigation fallback
let subtypeSmoke = 0;
for (const pb of kb.playbooks.values()) {
  const rbId = kb.registry.families[pb.attack_family].subtypes.find((x) => x.id === pb.subtype_id).runbook;
  const act = [...kb.actions.values()].find((a) => a.runbook_refs.includes(rbId));
  const gate = [...kb.policies.values()].find((p) => p.rule_type === "ACTION_GATE" && p.action_id === act.action_id && p.applicable_subtypes.includes(pb.subtype_id));
  const merged = synthesize(gate);
  const cls = synthesize({ required_evidence: pb.classification_evidence, required_targets: null, authority_requirements: null, authorization_gate: [] });
  for (const [k, v] of Object.entries(cls.evidence)) merged.evidence[k] = merged.evidence[k] ?? v;
  const plan = planIncident(kb, merged);
  subtypeSmoke++;
  if (!plan.active.includes(pb.subtype_id)) err(`smoke ${pb.subtype_id}: subtype not active with its own classification evidence`);
  if (!plan.ordered.some((n) => n.action_id === act.action_id)) err(`smoke ${pb.subtype_id}: primary action ${act.action_id} not ELIGIBLE/ordered (${plan.nodes.get(act.action_id)?.decision.decision}: ${plan.nodes.get(act.action_id)?.decision.reasons.map((r) => r.code)})`);
  const only = planIncident(kb, { evidence: cls.evidence });
  subtypeSmoke++;
  if (only.ordered.some((n) => n.action_id === act.action_id)) err(`smoke ${pb.subtype_id}: primary action ELIGIBLE on classification evidence alone (GL-1 violated)`);
  if (!only.ordered.some((n) => n.action_id === "ACT-INVESTIGATE-MISSING-EVIDENCE") && !only.ordered.some((n) => kb.actions.get(n.action_id).phase === "CONTAINMENT")) err(`smoke ${pb.subtype_id}: no investigation fallback`);
}

// ---- validation cases
let casesRun = 0, casesPass = 0;
const caseFails = [];
for (const c of kb.cases) {
  casesRun++;
  const plan = planIncident(kb, c.facts, c.mode ?? "platform_neutral");
  const fails = [];
  const exp = c.expect ?? {};
  if (exp.subtypes && JSON.stringify([...exp.subtypes].sort()) !== JSON.stringify([...plan.active].sort())) fails.push(`subtypes: expected ${exp.subtypes} got ${plan.active}`);
  if (exp.eligible_order && JSON.stringify(exp.eligible_order) !== JSON.stringify(plan.ordered.map((n) => n.action_id))) fails.push(`eligible order: expected ${exp.eligible_order} got ${plan.ordered.map((n) => n.action_id)}`);
  for (const [a, d] of Object.entries(exp.not_eligible ?? {})) { const n = plan.nodes.get(a); if (!n) fails.push(`${a}: not in plan (expected ${d})`); else if (n.decision.decision !== d) fails.push(`${a}: expected ${d} got ${n.decision.decision} [${n.decision.reasons.map((r) => r.code)}]`); }
  for (const a of exp.absent_actions ?? []) if (plan.nodes.has(a) && plan.nodes.get(a).decision.decision === "ELIGIBLE") fails.push(`${a}: must not be eligible`);
  if (exp.missing_evidence) { const got = new Set(plan.notEligible.flatMap((n) => n.decision.missing_evidence)); for (const e of exp.missing_evidence) if (!got.has(e)) fails.push(`missing evidence ${e} not reported`); }
  if (exp.missing_targets) { const got = new Set(plan.notEligible.flatMap((n) => n.decision.missing_targets)); for (const e of exp.missing_targets) if (!got.has(e)) fails.push(`missing target ${e} not reported`); }
  if (exp.variants) for (const [a, v] of Object.entries(exp.variants)) { const n = plan.nodes.get(a); if (n?.decision.variant !== v) fails.push(`${a}: variant expected ${v} got ${n?.decision.variant}`); }
  if (exp.flags) for (const [a, fl] of Object.entries(exp.flags)) { const n = plan.nodes.get(a); for (const f of fl) if (!n?.decision.flags.includes(f)) fails.push(`${a}: flag ${f} missing`); }
  if (exp.steps_included || exp.steps_omitted) {
    const inc = new Set(), omit = new Set();
    for (const n of plan.ordered) for (const rb of kb.actions.get(n.action_id).runbook_refs) { const s = selectSteps(kb, rb, plan.facts, n.decision.variant, 0, new Set(plan.ordered.map((o) => o.action_id))); s.included.forEach((x) => inc.add(`${x.runbook}:${x.step}`)); s.omitted.forEach((x) => omit.add(`${x.runbook}:${x.step}`)); }
    for (const s of exp.steps_included ?? []) if (!inc.has(s)) fails.push(`step ${s} should be included`);
    for (const s of exp.steps_omitted ?? []) if (!omit.has(s) || inc.has(s)) fails.push(`step ${s} should be omitted`);
  }
  if (plan.cyclic) fails.push("cyclic plan");
  if (fails.length) caseFails.push(`${c.case_id}: ${fails.join("; ")}`); else casesPass++;
}
for (const f of caseFails) err(`case ${f}`);
const cats = new Set(kb.cases.map((c) => c.category));
const needCats = ["evidence_complete", "evidence_insufficient", "target_incomplete", "authorized_benign", "multiple_branches", "critical_workload", "unsupported_capability", "missing_authority"];
for (const n of needCats) if (!cats.has(n)) err(`validation cases: category '${n}' has no case`);

// ---- migration map integrity (every "new" id must exist; every reference runbook must be a migration target)
{
  const mm = (await import("node:module")).createRequire(import.meta.url)("js-yaml").load(fs.readFileSync(path.join(ROOT, "migration-map.yaml"), "utf8"));
  const pbIds = new Set([...kb.playbooks.values()].map((p) => p.playbook_id));
  const chk = (sec, set, label) => { for (const e of mm[sec] ?? []) for (const n of Array.isArray(e.new) ? e.new : []) if (!set.has(n)) err(`migration-map ${sec}: ${n} (${label}) does not exist`); };
  chk("db_playbooks", pbIds, "playbook"); chk("actions", new Set(kb.actions.keys()), "action"); chk("runbooks", new Set(kb.runbooks.keys()), "runbook");
  const targeted = new Set((mm.runbooks ?? []).flatMap((e) => (Array.isArray(e.new) ? e.new : e.new ? [e.new] : [])));
  for (const rb of kb.runbooks.keys()) if (!targeted.has(rb)) warn(`runbook ${rb} is not a target of any legacy runbook in migration-map (new capability)`);
  const targetedAct = new Set((mm.actions ?? []).flatMap((e) => (Array.isArray(e.new) ? e.new : [])));
  for (const a of kb.actions.values()) for (const l of a.legacy_action_refs ?? []) if (!(mm.actions ?? []).some((e) => e.old.startsWith(l))) warn(`action ${a.action_id}: legacy ref ${l} missing from migration-map`);
}

// ---- RAG chunk invariant: no action/runbook chunk without its gates
const chunkList = buildChunks(kb);
for (const e of checkChunkInvariant(chunkList)) err(e);

// ---- report
const summary = { families: Object.keys(kb.registry.families).length, subtypes: matrix.length, playbooks: kb.playbooks.size, actions: kb.actions.size, policies: kb.policies.size, runbooks: kb.runbooks.size, evidence: kb.evidence.size, target_types: Object.keys(TT).length, policy_items_uncovered: uncovered.length, cases: `${casesPass}/${casesRun} pass`, rag_chunks: chunkList.length, policy_self_tests: selfTests, subtype_smoke_tests: subtypeSmoke };
console.log(JSON.stringify(summary, null, 2));
for (const w of warns) console.log("WARN  " + w);
for (const e of errors) console.log("ERROR " + e);
console.log(errors.length ? `\nFAILED: ${errors.length} error(s), ${warns.length} warning(s)` : `\nOK: 0 errors, ${warns.length} warning(s)`);

if (process.argv.includes("--write-matrix")) {
  const lines = ["# Subtype coverage matrix (generated by tools/validate.mjs --write-matrix — do not edit)", "", `Generated from ${matrix.length} reference subtypes. Columns: playbook exists · reference RB · action · ACTION_GATE policy(ies) · related branches.`, "", "| Family | Subtype | Name | Playbook | Reference RB | Action | Policy | Branches |", "|---|---|---|---|---|---|---|---|"];
  for (const r of matrix) lines.push(`| ${r.family} | ${r.subtype} | ${r.name} | ${r.playbook ? "✔" : "✘"} | ${r.runbook} | ${r.action} | ${r.policy} | ${r.branches} |`);
  lines.push("", "## Reference policy items → covering rules", "", "| Item | Text | Covered by |", "|---|---|---|");
  for (const [fam, def] of Object.entries(kb.registry.families)) for (const it of def.policy_items) lines.push(`| ${it.id} | ${it.text} | ${[...kb.policies.values()].filter((p) => (p.covers ?? []).includes(it.id)).map((p) => p.policy_id).join(", ") || "**NONE**"} |`);
  lines.push("", "## Global principles → covering rules", "", "| Principle | Covered by |", "|---|---|");
  for (const g of kb.registry.global_principles) lines.push(`| ${g.id} | ${[...kb.policies.values()].filter((p) => (p.covers ?? []).includes(g.id)).map((p) => p.policy_id).join(", ") || "**NONE**"} |`);
  fs.writeFileSync(path.join(ROOT, "coverage-matrix.md"), lines.join("\n") + "\n");
  console.log("wrote coverage-matrix.md");
}
process.exit(errors.length ? 1 : 0);
