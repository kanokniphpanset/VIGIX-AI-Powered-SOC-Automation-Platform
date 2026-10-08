import { collectLeaves, evalLeaf, evalPred } from "./predicate";
import { ActionDecision, DecisionReason, Facts, KnowledgeBase, PolicyDecision } from "./types";

/**
 * Deterministic policy evaluation for ONE action instance (port of the validated prototype semantics).
 *   PROHIBITED > NEEDS_EVIDENCE > NEEDS_TARGET > NEEDS_AUTHORIZATION > UNSUPPORTED > ELIGIBLE (headline); ALL reasons kept.
 * No LLM, no retrieval score, no confidence: only evidence / target / scope / authority / capability / context facts.
 * `inst` = target types validated for this instance (targets.<type>.validated).
 */
const FAIL_RANK: PolicyDecision[] = ["PROHIBITED", "NEEDS_EVIDENCE", "NEEDS_TARGET", "NEEDS_AUTHORIZATION", "UNSUPPORTED"];

export function evaluateAction(kb: KnowledgeBase, actionId: string, subtype: string, facts: Facts, inst?: Set<string>): ActionDecision {
  const policies = [...kb.policies.values()].filter(
    (p) => p.rule_type === "ACTION_GATE" && p.action_id === actionId && (p.applicable_subtypes!.includes("*") || p.applicable_subtypes!.includes(subtype))
  );
  const failing = new Set<PolicyDecision>();
  const reasons: DecisionReason[] = [];
  const flags = new Set<string>();
  const missingEvidence = new Set<string>();
  const missingTargets = new Set<string>();
  let variant: string | null = null;
  const done = (): ActionDecision => ({
    action_id: actionId, subtype, policies: policies.map((p) => p.policy_id),
    decision: FAIL_RANK.find((r) => failing.has(r)) ?? "ELIGIBLE", reasons, missing_evidence: [...missingEvidence], missing_targets: [...missingTargets], flags: [...flags], variant,
  });

  if (!policies.length) {
    failing.add("PROHIBITED");
    reasons.push({ code: "NO_POLICY", detail: `no ACTION_GATE policy for ${actionId} in ${subtype} (fail closed)` });
    return done();
  }
  for (const g of [...kb.policies.values()].filter((p) => p.rule_type === "GLOBAL_PROHIBITION")) {
    for (const pr of g.prohibitions ?? []) if (evalPred(pr.when, facts, inst) === "TRUE") { failing.add("PROHIBITED"); reasons.push({ code: pr.id, detail: pr.reason }); }
  }
  for (const p of policies) {
    for (const pr of p.prohibitions ?? []) if (evalPred(pr.when, facts, inst) === "TRUE") { failing.add("PROHIBITED"); reasons.push({ code: pr.id, detail: pr.reason }); }
    for (const ev of p.authorization_gate ?? []) {
      const e = facts.evidence.get(ev);
      if (e?.authorization === "AUTHORIZED") { failing.add("PROHIBITED"); reasons.push({ code: `AUTHORIZED:${ev}`, detail: `evidence ${ev} is AUTHORIZED (approved/benign activity)` }); }
      else if (e?.authorization !== "UNAUTHORIZED") { failing.add("NEEDS_EVIDENCE"); missingEvidence.add(ev); reasons.push({ code: `AUTHZ_UNKNOWN:${ev}`, detail: `authorization of ${ev} not established` }); }
    }
    if (evalPred(p.required_evidence, facts, inst) !== "TRUE") {
      failing.add("NEEDS_EVIDENCE");
      for (const l of collectLeaves(p.required_evidence)) if (evalLeaf(l, facts, inst) !== "TRUE") missingEvidence.add(l.field.split(".")[1]);
      reasons.push({ code: `${p.policy_id}:EVIDENCE`, detail: "required evidence not PRESENT" });
    }
    if (evalPred(p.required_targets, facts, inst) !== "TRUE") {
      failing.add("NEEDS_TARGET");
      for (const l of collectLeaves(p.required_targets)) if (evalLeaf(l, facts, inst) !== "TRUE") missingTargets.add(l.field.split(".")[1]);
      reasons.push({ code: `${p.policy_id}:TARGET`, detail: "target identity/scope not validated" });
    }
    // implicit authority: IR_TEAM executes every ticket; its absence in organization context is an explicit false, not unknown.
    if (facts.authority.get("ir_execute") !== true) { failing.add("NEEDS_AUTHORIZATION"); reasons.push({ code: "ir_execute", detail: "IR execution authority not granted" }); }
    if (evalPred(p.authority_requirements, facts, inst) !== "TRUE") { failing.add("NEEDS_AUTHORIZATION"); reasons.push({ code: `${p.policy_id}:AUTHORITY`, detail: "authority requirement not granted" }); }
    for (const c of p.criticality_constraints ?? []) {
      if (evalPred(c.when, facts, inst) !== "TRUE") continue;
      if (c.effect === "USE_VARIANT") { variant = c.variant ?? null; flags.add("VARIANT_SELECTED"); }
      if (c.effect === "REQUIRE_AUTHORITY" && facts.authority.get(c.authority!) !== true) { failing.add("NEEDS_AUTHORIZATION"); reasons.push({ code: `${p.policy_id}:CRIT_AUTH`, detail: `${c.authority} approval required for this criticality` }); }
      if (c.effect === "PROHIBIT") { failing.add("PROHIBITED"); reasons.push({ code: `${p.policy_id}:CRIT_PROHIBIT`, detail: c.reason ?? "prohibited by criticality" }); }
    }
    const capState = (cap: string): boolean | undefined => {
      const v = facts.capability.get(cap);
      return v === null || v === undefined ? undefined : v;
    };
    if (p.tool_capability_any_of?.length) {
      const vals = p.tool_capability_any_of.map(capState);
      const anyOk = vals.some((v) => v === true || (v === undefined && facts.mode !== "strict"));
      if (!anyOk) { failing.add("UNSUPPORTED"); reasons.push({ code: `${p.policy_id}:CAP_ANY`, detail: "none of the alternative capabilities is supported" }); }
      else if (vals.some((v) => v === undefined)) flags.add("TOOL_MAPPING_REQUIRED");
    }
    for (const cap of p.tool_capability_requirements ?? []) {
      const v = capState(cap);
      if (v === false || (v === undefined && facts.mode === "strict")) { failing.add("UNSUPPORTED"); reasons.push({ code: `${p.policy_id}:CAP`, detail: `${cap} not supported` }); }
      else if (v === undefined) flags.add("TOOL_MAPPING_REQUIRED");
    }
  }
  return done();
}

/** BRANCH_GATE: a related branch opens only if its gate's evidence holds and none of its prohibitions fires. */
export function evaluateBranchGate(kb: KnowledgeBase, gateId: string, originSubtype: string, facts: Facts): { ok: boolean; reason: string } {
  const p = kb.policies.get(gateId);
  if (!p || p.rule_type !== "BRANCH_GATE") return { ok: false, reason: "missing gate" };
  if (!(p.applicable_subtypes ?? []).includes(originSubtype)) return { ok: false, reason: "gate not applicable to origin" };
  for (const pr of p.prohibitions ?? []) if (evalPred(pr.when, facts) === "TRUE") return { ok: false, reason: pr.id };
  return { ok: evalPred(p.required_evidence, facts) === "TRUE", reason: "required_evidence" };
}
