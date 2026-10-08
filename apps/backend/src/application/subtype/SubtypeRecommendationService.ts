import { IRecommendationContextRepository, RehuntContextRow } from "../recommendation/ports/IRecommendationContextRepository";
import { SubtypeKnowledgeLoader, deployability } from "../../infrastructure/knowledge/SubtypeKnowledgeLoader";
import { makeStateAssessor } from "../../domain/subtype/actionState";
import { Composition, composePlan } from "../../domain/subtype/composer";
import { validateComposition } from "../../domain/subtype/outputValidator";
import { SubtypePlan, buildPlan } from "../../domain/subtype/planner";
import { Facts, KnowledgeBase } from "../../domain/subtype/types";
import { FactBuildResult, buildFacts } from "./factBuilder";

export type SubtypeMode = "off" | "shadow" | "enforce";

export function subtypeModeFromEnv(env: NodeJS.ProcessEnv = process.env): SubtypeMode {
  const v = (env.SUBTYPE_KNOWLEDGE_MODE ?? "shadow").toLowerCase();
  return v === "off" || v === "enforce" ? v : "shadow";
}

export interface SubtypeEvaluation {
  requestedMode: SubtypeMode;
  /** enforce only when requested AND the knowledge is deployable AND valid; otherwise shadow (with the reason). */
  effectiveMode: "shadow" | "enforce";
  fallbackReason: string | null;
  kb: KnowledgeBase;
  facts: Facts | null;
  plan: SubtypePlan | null;
  composition: Composition | null;
  /** output validator findings; non-empty => the composition was replaced by an investigation-only one. */
  violations: string[];
  audit: Record<string, unknown>;
}

/**
 * SubtypeRecommendationService - the production path from incident evidence to an approved plan:
 *   evidence rows (Evidence Contract v2 + analyst assertions) -> facts -> validated targets -> subtype/scenario -> policy decisions
 *   -> dependency ordering -> action-state overlay (tickets + re-hunt) -> deterministic composition -> output validation.
 * Reads only; it never calls a containment tool and never executes anything.
 */
export class SubtypeRecommendationService {
  constructor(
    private readonly loader: SubtypeKnowledgeLoader,
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly assets: { resolve(hosts: string[]): { criticality: string } },
    private readonly modeOf: () => SubtypeMode = subtypeModeFromEnv,
    private readonly strictCapabilities: boolean = process.env.SUBTYPE_STRICT_CAPABILITIES === "true"
  ) {}

  async evaluate(input: { incidentId: string; tenantId: string; investigationNumber: number; rehunt?: RehuntContextRow | null }): Promise<SubtypeEvaluation> {
    const requestedMode = this.modeOf();
    if (requestedMode === "off") {
      return { requestedMode, effectiveMode: "shadow", fallbackReason: "SUBTYPE_KNOWLEDGE_MODE=off", kb: this.loader.load(), facts: null, plan: null, composition: null, violations: [], audit: {} };
    }
    const kb = this.loader.load();
    const base = (over: Partial<SubtypeEvaluation>): SubtypeEvaluation => ({ requestedMode, effectiveMode: "shadow", fallbackReason: null, kb, facts: null, plan: null, composition: null, violations: [], audit: {}, ...over });
    if (kb.status !== "VALID") {
      return base({ fallbackReason: `knowledge INVALID: ${kb.errors.slice(0, 5).join(" | ")}`, audit: { knowledge: { version: kb.version, status: kb.status, errors: kb.errors } } });
    }
    const rows = (await this.contextRepository.getSubtypeEvidence?.(input.incidentId, input.tenantId, input.investigationNumber)) ?? [];
    const tickets = (await this.contextRepository.getTicketHistory?.(input.incidentId, input.tenantId)) ?? [];
    const hosts = [...new Set(rows.map((r) => r.host).filter((h): h is string => !!h))];
    const criticality = hosts.length ? this.assets.resolve(hosts).criticality : "UNKNOWN";
    const built: FactBuildResult = buildFacts(kb, { rows, assetCriticality: criticality, org: kb.organization, mode: this.strictCapabilities ? "strict" : "platform_neutral" });
    const rehunt = input.rehunt ?? null;
    const plan = buildPlan(kb, built.facts, {
      stateOf: makeStateAssessor(kb, {
        tickets, currentInvestigationNumber: input.investigationNumber,
        evidenceAt: (refs) => { const ts = rows.filter((r) => refs.includes(r.ref)).map((r) => r.timestamp.getTime()); return ts.length ? new Date(Math.max(...ts)) : null; },
        rehunt: rehunt ? { verifiedInvestigationNumber: rehunt.verifiedInvestigationNumber, result: rehunt.result, classification: rehunt.classification ?? null, coverageComplete: rehunt.coverageComplete ?? null, spreadDetected: rehunt.spreadDetected, matchingEvents: rehunt.matchingEvents, originalHosts: rehunt.originalHosts, affectedHosts: rehunt.affectedHosts, newHosts: rehunt.newHosts, verifiedAt: rehunt.verifiedAt ?? null } : null,
      }),
    });
    let composition = plan.cyclic ? composePlan(kb, { ...plan, ordered: [], suppressed: [] }) : composePlan(kb, plan);
    let violations = plan.cyclic ? ["CYCLIC_PLAN: dependency cycle detected - no action is opened"] : validateComposition(kb, plan, composition);
    if (violations.length) {
      // never publish a composition that failed validation, and never replace it with an ungated containment
      composition = composePlan(kb, { ...plan, ordered: [], suppressed: [] });
    }
    const dep = deployability(kb);
    let effectiveMode: "shadow" | "enforce" = "shadow";
    let fallbackReason: string | null = null;
    if (requestedMode === "enforce") {
      if (dep.deployable) effectiveMode = "enforce"; else fallbackReason = dep.reason;
    }
    const audit = this.buildAudit(kb, built, plan, composition, violations, { requestedMode, effectiveMode, fallbackReason, criticality, rehunt, ticketCount: tickets.length });
    return { requestedMode, effectiveMode, fallbackReason, kb, facts: built.facts, plan, composition, violations, audit };
  }

  private buildAudit(kb: KnowledgeBase, built: FactBuildResult, plan: SubtypePlan, comp: Composition, violations: string[], meta: Record<string, unknown>): Record<string, unknown> {
    const f = built.facts;
    return {
      knowledge: { version: kb.version, hash: kb.hash, status: kb.status, unreviewed: kb.unreviewed.length, organizationStatus: kb.organization.status },
      meta,
      selection: { subtypes: plan.active, openedBranches: plan.opened, scenarios: plan.instances.map((i) => ({ action: i.action_id, subtype: i.subtype, scenario: i.scenario_id })) },
      evidence: built.audit.evidence,
      targets: built.audit.candidates,
      ignoredInputs: built.audit.ignored,
      thresholds: built.audit.thresholds,
      policyDecisions: plan.instances.map((i) => ({
        instance: i.instanceKey, action: i.action_id, target: i.primary?.display ?? null, subtype: i.subtype, decision: i.decision.decision, policies: i.decision.policies, reasons: i.decision.reasons,
        flags: i.decision.flags, variant: i.decision.variant, missingEvidence: i.decision.missing_evidence, missingTargets: i.decision.missing_targets, ambiguousTargets: i.ambiguous,
        state: i.state, rehuntDecision: i.rehuntDecision, stateReason: i.stateReason, stateNeeds: i.stateNeeds, boundTargets: [...i.bindings.values()].map((t) => ({ type: t.type, identity: t.identityKey, refs: t.evidenceRefs })),
      })),
      ordering: plan.ordered.map((i, n) => ({ position: n + 1, instance: i.instanceKey, action: i.action_id, stage: i.stage, dependsOn: i.dependsOn, reason: i.orderReason })),
      suppressed: plan.suppressed.map((i) => ({ instance: i.instanceKey, state: i.state, rehuntDecision: i.rehuntDecision, reason: i.stateReason })),
      actionVersions: [...new Set(plan.ordered.map((i) => i.action_id))].map((a) => ({ action: a, runbooks: kb.actions.get(a)?.runbook_refs.map((r) => ({ runbook: r, review: kb.runbooks.get(r)?.review_status ?? "IR_REVIEW_PENDING" })), review: kb.actions.get(a)?.review_status ?? "IR_REVIEW_PENDING", knowledgeVersion: kb.version })),
      missingInfo: comp.missingInfo,
      omittedSteps: comp.omitted.filter((o) => o.omitted.length),
      stepReadiness: comp.readiness,
      authorityChecks: Object.fromEntries([...f.authority.entries()].map(([k, v]) => [k, v === null ? "UNKNOWN" : v])),
      capabilityChecks: Object.fromEntries([...f.capability.entries()].map(([k, v]) => [k, v === null ? "UNKNOWN" : v])),
      context: f.context,
      violations,
    };
  }
}
