import { RehuntDecision, StateAssessment } from "./actionState";
import { collectLeaves, evalPred } from "./predicate";
import { evaluateAction, evaluateBranchGate } from "./policyEngine";
import { ActionDecision, ActionDef, Facts, KnowledgeBase, PlaybookDef, Predicate, ResolvedTarget } from "./types";

/**
 * Subtype plan: classify (playbook classification_evidence) -> open branches (BRANCH_GATE) -> one INSTANCE per
 * (action, primary target identity) -> per-instance policy decision -> dependency/stage ordering -> dedupe.
 * Deterministic: tie-break is (containment stage, action_id, target identity), never file / retrieval / LLM order.
 * Deduplication key is action + target identity + variant - never text similarity - and never widens scope.
 */
export type InstanceState =
  | "NEW"                 // never proposed for this target
  | "PROPOSED_PENDING"    // proposed earlier, not executed yet
  | "EXECUTED_EFFECTIVE"  // executed + a covered re-hunt found no recurrence for this scope
  | "EXECUTED_UNVERIFIED" // executed, no usable verification yet (UNKNOWN - not "contained")
  | "RECURRED_CONTROL_UNKNOWN" // corroborated recurrence at this target, but the control state is unknown -> INVESTIGATE
  | "RECURRED_CONTROL_APPLIED" // corroborated recurrence although the IR attested the control was applied -> ADJUST (not a repeat)
  | "EXECUTED_NOT_APPLIED" // the IR recorded the control as not (fully) applied -> REPEAT
  | "FAILED";             // execution failed / ticket rejected-after-failure

export interface PlanInstance {
  instanceKey: string;
  action_id: string;
  subtype: string;
  scenario_id: string;
  primary: ResolvedTarget | null;
  /** target type -> bound validated target (primary + secondary, same host or unique). */
  bindings: Map<string, ResolvedTarget>;
  /** target types that had several candidates and no unambiguous binding. */
  ambiguous: string[];
  decision: ActionDecision;
  dependsOn: string[];
  orderReason: string;
  stage: ActionDef["containment_stage"];
  state: InstanceState;
  /** Why the instance is (not) proposed again after a re-hunt. */
  stateReason: string | null;
  /** What is still needed to settle an UNKNOWN state (e.g. coverage/telemetry); shown as information needed, never guessed. */
  stateNeeds: string[];
  /** next step chosen after a re-hunt (NEW / ADD / NO_NEW_ACTION / INVESTIGATE / REPEAT / ADJUST). */
  rehuntDecision: RehuntDecision;
  facts: Facts;
}

export interface SubtypePlan {
  active: string[];
  opened: string[];
  instances: PlanInstance[];
  ordered: PlanInstance[];
  notEligible: PlanInstance[];
  /** Eligible by policy but intentionally not proposed again (control still effective / awaiting verification). */
  suppressed: PlanInstance[];
  investigationFallback: boolean;
  cyclic: boolean;
}

export interface PlanOptions {
  /** state of an instance from earlier tickets + re-hunt (ActionStateAssessor). */
  stateOf?: (a: { action_id: string; primary: ResolvedTarget | null; instanceKey: string }) => StateAssessment;
}

const STAGE_RANK: Record<string, number> = { STOP_ACTIVE: 0, CLOSE_PATH: 1, IDENTITY_EXPOSURE: 2, CLEANUP_OBJECT: 3, NONE: 9 };
const targetLeafTypes = (p: Predicate | undefined): string[] => [...new Set(collectLeaves(p).filter((l) => l.field.startsWith("targets.")).map((l) => l.field.split(".")[1]))];

/** target types an action's policies/runbooks can use, in policy order (primary first). */
export function actionTargetTypes(kb: KnowledgeBase, action: ActionDef, subtype: string): { primaryCandidates: string[]; all: string[] } {
  const gates = [...kb.policies.values()].filter((p) => p.rule_type === "ACTION_GATE" && p.action_id === action.action_id && (p.applicable_subtypes!.includes("*") || p.applicable_subtypes!.includes(subtype)));
  const primary = [...new Set(gates.flatMap((g) => targetLeafTypes(g.required_targets)))];
  const used = new Set<string>();
  const scan = (rbId: string, depth = 0) => {
    const rb = kb.runbooks.get(rbId);
    if (!rb || depth > 3) return;
    for (const t of rb.required_targets) used.add(t);
    for (const s of rb.ordered_steps) {
      for (const m of s.instruction.matchAll(/\{\{([a-z_]+)\.[a-z_]+\}\}/g)) if (m[1] !== "missing") used.add(m[1]);
      for (const t of targetLeafTypes(s.condition)) used.add(t);
      if (s.include_runbook) scan(s.include_runbook, depth + 1);
    }
  };
  for (const r of action.runbook_refs) scan(r);
  const all = [...new Set([...primary, ...used])].filter((t) => kb.targetTypes.has(t));
  return { primaryCandidates: primary.length ? primary : action.target_requirements, all };
}

function bindSecondary(types: string[], primary: ResolvedTarget | null, facts: Facts): { bound: ResolvedTarget[]; ambiguous: string[] } {
  const bound: ResolvedTarget[] = [];
  const ambiguous: string[] = [];
  for (const type of types) {
    const cands = facts.targets.filter((t) => t.type === type && t.validated);
    if (!cands.length) continue;
    const sameHost = primary?.hostKey ? cands.filter((c) => c.hostKey === primary.hostKey) : [];
    const pool = sameHost.length ? sameHost : cands;
    // never pick one of several different targets silently: ambiguity is reported, not guessed
    if (new Set(pool.map((c) => c.identityKey)).size === 1) bound.push(pool[0]);
    else ambiguous.push(type);
  }
  return { bound, ambiguous };
}

export function instanceFacts(base: Facts, targets: ResolvedTarget[]): { facts: Facts; inst: Set<string> } {
  const scope = new Set(base.scope);
  for (const t of targets) for (const f of t.scopeFlags) scope.add(f);
  return { facts: { ...base, scope }, inst: new Set(targets.filter((t) => t.validated).map((t) => t.type)) };
}

export function activePlaybooks(kb: KnowledgeBase, facts: Facts): { active: PlaybookDef[]; opened: string[] } {
  const eff = new Map<string, PlaybookDef>();
  for (const pb of [...kb.playbooks.values()].sort((a, b) => a.subtype_id.localeCompare(b.subtype_id))) {
    if (evalPred(pb.classification_evidence, facts) === "TRUE") eff.set(pb.subtype_id, pb);
  }
  const opened: string[] = [];
  const queue = [...eff.values()];
  while (queue.length) {
    const pb = queue.shift()!;
    for (const br of pb.related_branches ?? []) {
      if (eff.has(br.subtype_id) || evalPred(br.open_when, facts) !== "TRUE") continue;
      if (br.gate_policy && !evaluateBranchGate(kb, br.gate_policy, pb.subtype_id, facts).ok) continue;
      const next = kb.playbooks.get(br.subtype_id);
      if (!next) continue;
      eff.set(br.subtype_id, next);
      opened.push(`${pb.subtype_id}->${br.subtype_id}`);
      queue.push(next);
    }
  }
  return { active: [...eff.values()], opened };
}

export function buildPlan(kb: KnowledgeBase, facts: Facts, options: PlanOptions = {}): SubtypePlan {
  const { active, opened } = activePlaybooks(kb, facts);
  const byKey = new Map<string, PlanInstance>();

  for (const pb of active) {
    for (const sc of pb.scenarios) {
      if (sc.when && evalPred(sc.when, facts) !== "TRUE") continue;
      for (const ref of sc.ordered_action_refs) {
        const action = kb.actions.get(ref.action_id);
        if (!action) continue;
        const { primaryCandidates, all } = actionTargetTypes(kb, action, pb.subtype_id);
        const validated = facts.targets.filter((t) => t.validated);
        const primaryType = primaryCandidates.find((t) => validated.some((v) => v.type === t));
        const primaries: (ResolvedTarget | null)[] = primaryType ? validated.filter((t) => t.type === primaryType) : [null];
        for (const primary of primaries) {
          const { bound, ambiguous } = bindSecondary(all.filter((t) => t !== primaryType), primary, facts);
          const targets = [...(primary ? [primary] : []), ...bound];
          const { facts: iFacts, inst } = instanceFacts(facts, targets);
          const decision = evaluateAction(kb, ref.action_id, pb.subtype_id, iFacts, inst);
          if (ref.condition !== "POLICY_ELIGIBLE" && decision.decision === "ELIGIBLE" && evalPred(ref.condition, iFacts, inst) !== "TRUE") {
            decision.decision = "NEEDS_EVIDENCE";
            decision.reasons.push({ code: "SCENARIO_CONDITION", detail: "scenario-specific condition not TRUE" });
          }
          const instanceKey = `${ref.action_id}|${primary?.identityKey ?? "-"}`;
          const prev = byKey.get(instanceKey);
          const node: PlanInstance = {
            instanceKey, action_id: ref.action_id, subtype: pb.subtype_id, scenario_id: sc.scenario_id, primary, bindings: new Map(targets.map((t) => [t.type, t])), ambiguous,
            decision, dependsOn: [...ref.depends_on], orderReason: ref.order_reason, stage: action.containment_stage, state: "NEW", stateReason: null, stateNeeds: [], rehuntDecision: "NEW", facts: iFacts,
          };
          if (!prev) byKey.set(instanceKey, node);
          else {
            prev.dependsOn = [...new Set([...prev.dependsOn, ...ref.depends_on])];
            if (prev.decision.decision !== "ELIGIBLE" && decision.decision === "ELIGIBLE") Object.assign(prev, { ...node, dependsOn: prev.dependsOn });
          }
        }
      }
    }
  }

  const instances = [...byKey.values()];
  for (const n of instances) {
    if (options.stateOf) { const s = options.stateOf({ action_id: n.action_id, primary: n.primary, instanceKey: n.instanceKey }); n.state = s.state; n.stateReason = s.reason; n.stateNeeds = s.needs ?? []; n.rehuntDecision = s.decision; }
  }
  // Re-proposal policy: an instance whose control is still effective (or whose result is unknown / pending) is not proposed again.
  const SUPPRESS = new Set(["EXECUTED_EFFECTIVE", "EXECUTED_UNVERIFIED", "PROPOSED_PENDING", "RECURRED_CONTROL_UNKNOWN", "RECURRED_CONTROL_APPLIED"]);
  const eligibleAll = instances.filter((n) => n.decision.decision === "ELIGIBLE");
  const suppressed = eligibleAll.filter((n) => SUPPRESS.has(n.state));
  const eligible = eligibleAll.filter((n) => !SUPPRESS.has(n.state));
  const notEligible = instances.filter((n) => n.decision.decision !== "ELIGIBLE");

  const included = new Map(eligible.map((n) => [n.instanceKey, n]));
  const depsOf = (n: PlanInstance) => eligible.filter((m) => m !== n && n.dependsOn.includes(m.action_id));
  const indeg = new Map(eligible.map((n) => [n.instanceKey, depsOf(n).length]));
  const ordered: PlanInstance[] = [];
  const ready = eligible.filter((n) => indeg.get(n.instanceKey) === 0);
  while (ready.length) {
    ready.sort((a, b) => (STAGE_RANK[a.stage] ?? 9) - (STAGE_RANK[b.stage] ?? 9) || a.action_id.localeCompare(b.action_id) || a.instanceKey.localeCompare(b.instanceKey));
    const n = ready.shift()!;
    ordered.push(n);
    for (const m of eligible) if (m !== n && m.dependsOn.includes(n.action_id) && included.has(m.instanceKey)) {
      indeg.set(m.instanceKey, indeg.get(m.instanceKey)! - 1);
      if (indeg.get(m.instanceKey) === 0 && !ready.includes(m) && !ordered.includes(m)) ready.push(m);
    }
  }
  const cyclic = ordered.length !== eligible.length;
  const hasContainment = ordered.some((n) => kb.actions.get(n.action_id)?.phase === "CONTAINMENT");
  return { active: active.map((p) => p.subtype_id), opened, instances, ordered: cyclic ? [] : ordered, notEligible, suppressed, investigationFallback: !hasContainment, cyclic };
}
