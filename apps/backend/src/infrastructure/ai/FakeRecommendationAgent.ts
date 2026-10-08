import { evaluateActionEvidence } from "../../application/recommendation/services/ActionEvidence";
import { applicableProcedure } from "../../application/recommendation/services/ProcedureApplicability";
import { IRecommendationAgentPort } from "../../application/recommendation/ports/IRecommendationAgentPort";
import {
  RecommendationContextActionProcedure,
  RecommendationContextContainmentProcedure,
  RecommendationContextDto,
  RecommendationContextPlaybook,
  isRecommendable,
  stepKey,
  noveltyHistory,
} from "../../application/recommendation/dto/RecommendationContextDto";

/**
 * FakeRecommendationAgent — deterministic, non-LLM RecommendationAgent used
 * when RECOMMENDATION_AGENT is not "llm" (and in tests). Produces a v2
 * (Task 10.3) action-level candidate using ONLY what the backend put in the
 * context: the selected playbook, its allowed Actions in strategy order, each
 * Action's runbook procedure (as instructions applied to the target) and the
 * Policy role. It never restates the Core Flow and never invents a value.
 *
 * Primary action = the first allowed Action with a recorded target of its
 * kind; further allowed Actions with a target are added too, except account
 * disabling, which is only primary (the playbooks make it conditional on
 * compromise evidence this heuristic cannot judge). No playbook or no
 * targetable Action -> an empty candidate, which the validator rejects —
 * nothing is fabricated to fill the gap.
 *
 * With an attack-specific containment procedure in the context, it follows the procedure in order instead: every
 * step's CHECK items become one CHECK step; the first procedure step holding a recommendable Action with a recorded
 * target supplies the ACTION steps (each carrying its procedure condition) and that step's MANUAL controls. Later
 * Actions declared conditional by applicable knowledge can follow later CHECKs, carrying their human-confirmed
 * precondition; the agent never claims the condition has been met. Required MANUAL controls remain non-executable.
 * Other later actions remain omitted except for one new pair when every primary pair was already proposed.
 */
export class FakeRecommendationAgent implements IRecommendationAgentPort {
  async generate(context: RecommendationContextDto): Promise<unknown> {
    const playbook = context.playbook ?? null;
    const procedures = context.actionProcedures ?? [];
    if (context.investigationOnly && context.containmentProcedure) return this.fromUnknown(context, context.containmentProcedure);
    if (!playbook || procedures.length === 0) {
      return { summary: `No incident-level playbook applies to "${context.incidentTitle}"; no response action can be recommended.`, steps: [] };
    }
    if (context.containmentProcedure) return this.fromProcedure(context, playbook, procedures, applicableProcedure(context.containmentProcedure, context)!);

    // A later Recommendation of the incident needs at least one Action + target pair not proposed before: prefer an
    // unused target, and let account disabling in when it is the only new pair.
    const proposed = new Set(noveltyHistory(context).map((s) => stepKey(s.actionCode, s.target)));
    const isNew = (c: { procedure: RecommendationContextActionProcedure; target: string }) => !proposed.has(stepKey(c.procedure.actionCode, c.target));
    const chosen: { procedure: RecommendationContextActionProcedure; target: string }[] = [];
    for (const procedure of procedures) {
      if (!isRecommendable(procedure)) continue;
      const targets = this.targetsFor(context, procedure.actionCode);
      const target = targets.find((t) => !proposed.has(stepKey(procedure.actionCode, t))) ?? targets[0];
      if (!target) continue;
      const pick = { procedure, target };
      const neededAsNew = proposed.size > 0 && isNew(pick) && !chosen.some(isNew);
      if (procedure.actionCode === "ACT-DISABLE-ACCOUNT" && chosen.length > 0 && !neededAsNew) continue;
      chosen.push(pick);
    }

    const steps = chosen.map(({ procedure, target }, i) => {
      // Cite by the backend's stable ids only: the target's IOC id, the evidence rows naming it, the MITRE techniques.
      const evidenceRefs = [
        ...context.iocs.filter((i) => i.iocValue === target && i.ref).map((i) => i.ref as string),
        ...context.evidence.filter((e) => e.ref && (e.host === target || e.iocValues.includes(target))).map((e) => e.ref as string),
        ...context.mitreMappings.map((m) => m.techniqueId),
      ];
      return {
        stepOrder: i + 1,
        action: procedure.actionCode,
        objective: procedure.runbookObjective ?? `${procedure.actionName} on ${target}.`,
        responsibleRole: procedure.policy.responsibleRole ?? "",
        target,
        reason: `${playbook.incidentType} incident (${playbook.matchedTechniques.join(", ")}); ${target} is recorded in this investigation's evidence.`,
        evidenceRefs,
        instructions: procedure.procedure.map((instruction, n) => ({ order: n + 1, instruction, target, expectedResult: null })),
        playbook: playbook.code,
        runbook: procedure.runbookCode ?? "",
        verificationCriteria: procedure.verificationCriteria.join(" ") || `${procedure.actionName} is confirmed in effect for ${target}.`,
        expectedResult: procedure.expectedResult,
        missingEvidence: [],
        confidence: 0.5,
        requiresApprovalSuggested: procedure.policy.approvalRequired,
      };
    });

    return {
      summary: `${playbook.name}: ${chosen.map((c) => `${c.procedure.actionName} (${c.target})`).join("; ") || "no targetable action in the evidence"}.`,
      steps,
    };
  }

  private fromProcedure(
    context: RecommendationContextDto,
    playbook: RecommendationContextPlaybook,
    procedures: RecommendationContextActionProcedure[],
    procedure: RecommendationContextContainmentProcedure
  ): unknown {
    const byCode = new Map(procedures.map((p) => [p.actionCode, p]));
    const proposed = new Set(noveltyHistory(context).map((s) => stepKey(s.actionCode, s.target)));
    const pick = (code: string | null) => {
      const p = code ? byCode.get(code) : undefined;
      if (!p || !isRecommendable(p)) return null;
      const targets = this.targetsFor(context, p.actionCode);
      const target = targets.find((t) => !proposed.has(stepKey(p.actionCode, t))) ?? targets[0];
      return target ? { procedure: p, target } : null;
    };
    const primary = procedure.steps.find((s) => s.items.some((i) => i.type === "ACTION" && pick(i.actionCode)));
    const primaryPairs = primary ? primary.items.filter((i) => i.type === "ACTION").map((i) => ({ item: i, chosen: pick(i.actionCode) })).filter((x) => x.chosen) : [];
    const needsNew = proposed.size > 0 && primaryPairs.every((x) => proposed.has(stepKey(x.chosen!.procedure.actionCode, x.chosen!.target)));
    let extraUsed = false;
    const mitre = context.mitreMappings.map((m) => m.techniqueId);

    const steps: Record<string, unknown>[] = [];
    const push = (step: Record<string, unknown>) => steps.push({ stepOrder: steps.length + 1, playbook: playbook.code, missingEvidence: [], confidence: 0.5, ...step });
    for (const ps of procedure.steps) {
      const checks = ps.items.filter((i) => i.type === "CHECK");
      if (checks.length) {
        push({
          type: "CHECK", phase: ps.phase, status: "SUPPORTED", action: null, runbook: null, procedureStep: ps.stepOrder, condition: null, target: null,
          objective: ps.objective, responsibleRole: ps.responsibleRole, reason: ps.reason, evidenceRefs: mitre,
          instructions: checks.map((c, n) => ({ order: n + 1, instruction: c.text, target: null, expectedResult: null })),
          verificationCriteria: ps.expectedResult, expectedResult: ps.expectedResult, requiresApprovalSuggested: false,
        });
      }
      const isPrimary = ps === primary;
      for (const item of ps.items.filter((i) => i.type === "ACTION")) {
        const chosen = pick(item.actionCode);
        if (!chosen) continue;
        const isNew = !proposed.has(stepKey(chosen.procedure.actionCode, chosen.target));
        if (!isPrimary && !ps.conditionalActions && !(needsNew && isNew && !extraUsed)) continue;
        if (!isPrimary) extraUsed = true;
        push({ ...this.actionStep(context, playbook, chosen.procedure, chosen.target, item.condition, ps.stepOrder), phase: ps.phase, status: item.condition ? "CONDITIONAL" : "SUPPORTED" });
      }
      const manualOnlyContainment = ps.phase === "SELECT_ACTION" && !ps.items.some((i) => i.type === "ACTION");
      if (isPrimary || manualOnlyContainment || ps.requiredTypes?.includes("MANUAL")) {
        for (const item of ps.items.filter((i) => i.type === "MANUAL")) {
          push({
            type: "MANUAL", phase: ps.phase, status: item.condition ? "CONDITIONAL" : "SUPPORTED", action: null, runbook: null, procedureStep: ps.stepOrder, condition: item.condition, target: null,
            objective: item.text, responsibleRole: ps.responsibleRole, reason: ps.reason, evidenceRefs: mitre,
            instructions: [{ order: 1, instruction: item.text, target: null, expectedResult: null }],
            verificationCriteria: ps.expectedResult, expectedResult: ps.expectedResult, requiresApprovalSuggested: item.requiresApproval,
          });
        }
      }
    }
    const actions = steps.filter((s) => s.type === "ACTION").map((s) => `${s.action} (${s.target})`);
    return { summary: `${procedure.objective} ${procedure.strategy}${actions.length ? ` Actions: ${actions.join("; ")}.` : ""}`, steps };
  }

  /**
   * UNKNOWN_INCIDENT: no attack-specific playbook. The built-in investigation procedure supplies the CHECK steps; each
   * retrieved knowledge item (if any) supplies one more step, citing the item. No catalog Action is ever offered, and
   * nothing is invented to make the plan look like a full response lifecycle.
   */
  private fromUnknown(context: RecommendationContextDto, procedure: RecommendationContextContainmentProcedure): unknown {
    const mitre = context.mitreMappings.map((m) => m.techniqueId);
    const steps: Record<string, unknown>[] = [];
    const push = (step: Record<string, unknown>) => steps.push({ stepOrder: steps.length + 1, missingEvidence: [], confidence: 0.4, ...step });
    for (const ps of procedure.steps) {
      push({
        type: "CHECK", phase: ps.phase, status: "SUPPORTED", action: null, runbook: null, playbook: null, procedureStep: ps.stepOrder, condition: null, target: null,
        objective: ps.objective, responsibleRole: ps.responsibleRole, reason: ps.reason, evidenceRefs: mitre,
        instructions: ps.items.map((c, n) => ({ order: n + 1, instruction: c.text, target: null, expectedResult: null })),
        verificationCriteria: ps.expectedResult, expectedResult: ps.expectedResult, requiresApprovalSuggested: false,
      });
    }
    for (const k of context.retrievedKnowledge ?? []) {
      push({
        type: k.kind, phase: k.phase, status: "SUPPORTED", action: null, runbook: null, playbook: null, procedureStep: null,
        condition: k.kind === "MANUAL" ? "The analyst confirms the incident evidence matches the retrieved knowledge." : null, target: null,
        objective: k.guidance, responsibleRole: "IR_TEAM", reason: `Supported by ${k.source.replace("_", " ").toLowerCase()} "${k.title}".`,
        evidenceRefs: mitre, knowledgeRefs: [k.ref],
        instructions: [{ order: 1, instruction: k.guidance, target: null, expectedResult: null }],
        verificationCriteria: k.guidance, expectedResult: null, requiresApprovalSuggested: k.requiresApproval,
      });
    }
    return {
      summary: `No attack-specific playbook applies to "${context.incidentTitle}": investigate first${(context.retrievedKnowledge ?? []).length ? ", then follow the retrieved knowledge" : ""}.`,
      steps,
    };
  }

  private actionStep(
    context: RecommendationContextDto,
    playbook: RecommendationContextPlaybook,
    procedure: RecommendationContextActionProcedure,
    target: string,
    condition: string | null,
    procedureStep: number
  ): Record<string, unknown> {
    return {
      type: "ACTION",
      action: procedure.actionCode,
      condition,
      procedureStep,
      objective: procedure.runbookObjective ?? `${procedure.actionName} on ${target}.`,
      responsibleRole: procedure.policy.responsibleRole ?? "",
      target,
      reason: `${playbook.incidentType} incident (${playbook.matchedTechniques.join(", ")}); ${target} is recorded in this investigation's evidence.`,
      evidenceRefs: [
        ...context.iocs.filter((i) => i.iocValue === target && i.ref).map((i) => i.ref as string),
        ...context.evidence.filter((e) => e.ref && (e.host === target || e.iocValues.includes(target))).map((e) => e.ref as string),
        ...context.mitreMappings.map((m) => m.techniqueId),
      ],
      instructions: procedure.procedure.map((instruction, n) => ({ order: n + 1, instruction, target, expectedResult: null })),
      runbook: procedure.runbookCode ?? "",
      verificationCriteria: procedure.verificationCriteria.join(" ") || `${procedure.actionName} is confirmed in effect for ${target}.`,
      expectedResult: procedure.expectedResult,
      requiresApprovalSuggested: procedure.policy.approvalRequired,
    };
  }

  private targetsFor(context: RecommendationContextDto, actionCode: string): string[] {
    const p = context.actionProcedures?.find(p => p.actionCode === actionCode);
    return evaluateActionEvidence(context, actionCode, p?.compliance?.requiredEvidence ?? []).targets;
  }
}
