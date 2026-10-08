// build-chunks.mjs — builds RAG chunks (+ metadata) from the knowledge so that an ACTION chunk can never be retrieved WITHOUT its gates.
// usage: node build-chunks.mjs [--write]   -> rag/chunks.jsonl     (validate.mjs imports buildChunks() and asserts the gate-completeness invariant)
import fs from "node:fs";
import path from "node:path";
import { loadAll, ROOT, collectLeaves } from "./lib.mjs";

const predText = (p) => {
  if (!p) return "—";
  if (p.field) return `${p.field} ${p.operator} ${JSON.stringify(p.value)}`;
  const k = ["all_of", "any_of", "none_of"].find((x) => p[x]);
  return p[k].length ? `${k}(${p[k].map(predText).join("; ")})` : "—";
};

export function buildChunks(kb) {
  const out = [];
  const base = (o) => ({ language: "th", status: "ACTIVE", version: "2.0.0", ...o });
  // 1) evidence catalog (one chunk per family)
  for (const f of kb.families) {
    if (!f.evidence?.length) continue;
    out.push(base({
      chunk_id: `evidence:${f.family}`, knowledge_type: "evidence_catalog", knowledge_id: `EVC-${f.family}`, attack_family: f.family,
      text: f.evidence.map((e) => `[${e.id}] ${e.description} | ยืนยันโดย: ${e.confirm} | อาจเป็น AUTHORIZED: ${e.may_be_authorized}`).join("\n"),
      provenance: { file: `families/${f.file}` },
    }));
  }
  // 2) target types (one chunk each)
  for (const [id, t] of Object.entries(kb.targetTypes)) out.push(base({
    chunk_id: `target:${id}`, knowledge_type: "target_type", knowledge_id: `TGT-${id}`, target_types: [id],
    text: `${id} (${t.label_th}): ${t.description} | required_identity_fields: ${t.required_identity_fields.join(", ")} | validation: ${t.validation_rules.join(" ; ")} | exclusions: ${(t.exclusions ?? []).join(" ; ")}`,
    provenance: { file: "contracts/target-types.yaml" },
  }));
  // 3) playbook scenario chunks — carry classification evidence, insufficient evidence, ordered actions with dependencies + reasons, branches
  for (const pb of kb.playbooks.values()) for (const sc of pb.scenarios) out.push(base({
    chunk_id: `playbook:${pb.subtype_id}:${sc.scenario_id}`, knowledge_type: "playbook_scenario", knowledge_id: pb.playbook_id, attack_family: pb.attack_family, subtype_id: pb.subtype_id, scenario_id: sc.scenario_id,
    action_ids: sc.ordered_action_refs.map((r) => r.action_id), policy_refs: pb.policy_refs,
    text: [`${pb.subtype_name} / ${sc.description}`, `classification: ${predText(pb.classification_evidence)}`, `ไม่เพียงพอ: ${pb.insufficient_evidence.join(" ; ")}`,
      `ลำดับ: ${sc.ordered_action_refs.map((r) => `${r.action_id} (depends_on ${r.depends_on.join(",") || "-"}; ${r.order_reason})`).join(" -> ")}`,
      `branches: ${(pb.related_branches ?? []).map((b) => `${b.subtype_id} เมื่อ ${predText(b.open_when)}`).join(" ; ") || "-"}`,
      `stop/escalate: ${(pb.stop_escalation ?? []).map((s) => `${s.then}: ${s.note}`).join(" ; ")}`].join("\n"),
    provenance: pb.provenance,
  }));
  // 4) ACTION + POLICY chunks — required evidence, targets, prohibitions, authority, capability, criticality, dependencies are ALWAYS inside the chunk
  const depsOf = (aid) => [...kb.playbooks.values()].flatMap((pb) => pb.scenarios.flatMap((sc) => sc.ordered_action_refs.filter((r) => r.action_id === aid).map((r) => `${pb.subtype_id}: depends_on [${r.depends_on.join(",")}] — ${r.order_reason}`)));
  for (const a of kb.actions.values()) {
    const gates = [...kb.policies.values()].filter((p) => p.rule_type === "ACTION_GATE" && p.action_id === a.action_id);
    for (const g of gates) out.push(base({
      chunk_id: `action:${a.action_id}:${g.policy_id}`, knowledge_type: "action_policy", knowledge_id: g.policy_id, action_id: a.action_id, runbook_id: a.runbook_refs[0],
      attack_family: [...new Set(g.applicable_subtypes.map((s) => kb.playbooks.get(s)?.attack_family).filter(Boolean))], subtype_id: g.applicable_subtypes,
      target_types: a.target_requirements, tools: [...(g.tool_capability_requirements ?? []), ...(g.tool_capability_any_of ?? [])],
      gates_present: true,
      text: [`ACTION ${a.action_id}: ${a.action_name} — ${a.objective}`, `phase/stage: ${a.phase}/${a.containment_stage}`, `ใช้ได้กับ subtype: ${g.applicable_subtypes.join(", ")}`,
        `required_evidence: ${predText(g.required_evidence)}`, `required_targets: ${predText(g.required_targets)}`,
        `authorization_gate: ${(g.authorization_gate ?? []).join(", ") || "-"}`,
        `prohibitions: ${(g.prohibitions ?? []).map((p) => `${p.id}: ${p.reason}`).join(" ; ") || "-"}`,
        `authority: ir_execute + ${predText(g.authority_requirements)}`, `capability: ${[...(g.tool_capability_requirements ?? []), ...(g.tool_capability_any_of ?? []).map((c) => c + "(any)")].join(", ") || "-"}`,
        `criticality: ${(g.criticality_constraints ?? []).map((c) => `${c.effect} ${c.variant ?? c.authority ?? ""} when ${predText(c.when)}`).join(" ; ") || "-"}`,
        `dependencies: ${depsOf(a.action_id).join(" | ") || "-"}`, `execution_constraints: ${a.execution_constraints.join(" ; ")}`, `fallback: ${g.fallback ? g.fallback.action_id + " — " + g.fallback.when : "-"}`].join("\n"),
      provenance: g.provenance,
    }));
  }
  // 5) runbook chunks per step group (kept whole; steps carry preconditions/bindings)
  for (const r of kb.runbooks.values()) out.push(base({
    chunk_id: `runbook:${r.runbook_id}`, knowledge_type: "runbook", knowledge_id: r.runbook_id, runbook_id: r.runbook_id, action_id: r.supported_action_ids, subtype_id: r.supported_subtypes, target_types: r.required_targets, tools: r.required_capabilities,
    gates_present: true,
    text: [`RUNBOOK ${r.runbook_id}: ${r.objective}`, `prerequisites: ${r.prerequisites.join(" ; ")}`, `required_evidence: ${r.required_evidence.join(", ")}`, `required_targets: ${r.required_targets.join(", ") || "(per-step conditions)"}`,
      `authority: ${r.required_authority.join(", ")}`, `impact: ${r.operational_impact}`,
      ...r.ordered_steps.map((s) => `${s.step_id}${s.variant ? `[${s.variant}]` : ""}${s.fold ? "[precheck]" : ""}${s.manual_owner ? `[MANUAL:${s.manual_owner}]` : ""}: ${s.instruction} | condition: ${predText(s.condition)} | ผลที่คาดหวัง: ${s.expected_result} | ตรวจ: ${s.verify} | ถ้าไม่สำเร็จ: ${s.on_failure}${s.rollback ? ` | rollback: ${s.rollback}` : ""}`),
      `verification: ${r.verification.join(" ; ")}`, `failure_handling: ${r.failure_handling.join(" ; ")}`].join("\n"),
    provenance: { file: `families/${r.__file}` },
  }));
  // 6) global rules
  for (const p of kb.policies.values()) if (["GLOBAL_PROHIBITION", "OUTPUT_CONSTRAINT", "CLASSIFICATION_RULE", "BRANCH_GATE"].includes(p.rule_type)) out.push(base({
    chunk_id: `rule:${p.policy_id}`, knowledge_type: "policy_rule", knowledge_id: p.policy_id, rule_type: p.rule_type, applicable_subtype: p.applicable_subtypes ?? "*",
    text: `${p.policy_id} (${p.rule_type}) covers ${(p.covers ?? []).join(",")}: ${p.reason}\n` + [...(p.prohibitions ?? []).map((x) => `${x.id}: ${x.reason}`), ...(p.checks ?? []).map((c) => `${c.check_id}: ${c.rule}`), ...(p.statements ?? [])].join("\n"),
    provenance: p.provenance,
  }));
  return out;
}

export function checkChunkInvariant(chunks) {
  const errs = [];
  for (const c of chunks) {
    if (c.knowledge_type === "action_policy") for (const k of ["required_evidence:", "required_targets:", "prohibitions:", "authority:", "dependencies:", "capability:"]) if (!c.text.includes(k)) errs.push(`chunk ${c.chunk_id} lacks '${k}'`);
    if (c.knowledge_type === "runbook") for (const k of ["required_evidence:", "required_targets:", "authority:"]) if (!c.text.includes(k)) errs.push(`chunk ${c.chunk_id} lacks '${k}'`);
    if (!c.knowledge_id || !c.knowledge_type || !c.provenance) errs.push(`chunk ${c.chunk_id} missing mandatory metadata`);
  }
  return errs;
}

if (process.argv[1]?.endsWith("build-chunks.mjs")) {
  const kb = loadAll();
  const chunks = buildChunks(kb);
  const errs = checkChunkInvariant(chunks);
  console.log(`${chunks.length} chunks; invariant violations: ${errs.length}`);
  errs.forEach((e) => console.log("ERROR " + e));
  if (process.argv.includes("--write")) {
    fs.mkdirSync(path.join(ROOT, "rag"), { recursive: true });
    fs.writeFileSync(path.join(ROOT, "rag/chunks.jsonl"), chunks.map((c) => JSON.stringify(c)).join("\n") + "\n");
    console.log("wrote rag/chunks.jsonl");
  }
  process.exit(errs.length ? 1 : 0);
}
