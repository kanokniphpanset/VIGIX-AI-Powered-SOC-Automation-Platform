import { IRecommendationAgentPort } from "../../application/recommendation/ports/IRecommendationAgentPort";
import {
  RecommendationContextActionProcedure,
  RecommendationContextDto,
  targetableIocValues,
} from "../../application/recommendation/dto/RecommendationContextDto";

/** Which recorded value kind each containment action targets (mirrors RecommendationValidator). */
const TARGET_KIND: Record<string, "ip" | "domain" | "url" | "account" | "host"> = {
  "ACT-BLOCK-SOURCE-IP": "ip",
  "ACT-BLOCK-DOMAIN": "domain",
  "ACT-BLOCK-URL": "url",
  "ACT-DISABLE-ACCOUNT": "account",
  "ACT-ISOLATE-ENDPOINT": "host",
};

const IOC_KIND: Record<string, string> = { ipv4: "ip", ipv6: "ip", ip: "ip", domain: "domain", url: "url", username: "account", user: "account" };

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
 */
export class FakeRecommendationAgent implements IRecommendationAgentPort {
  async generate(context: RecommendationContextDto): Promise<unknown> {
    const playbook = context.playbook ?? null;
    const procedures = context.actionProcedures ?? [];
    if (!playbook || procedures.length === 0) {
      return { summary: `No incident-level playbook applies to "${context.incidentTitle}"; no response action can be recommended.`, steps: [] };
    }

    const chosen: { procedure: RecommendationContextActionProcedure; target: string }[] = [];
    for (const procedure of procedures) {
      const target = this.targetFor(context, procedure.actionCode);
      if (!target) continue;
      if (procedure.actionCode === "ACT-DISABLE-ACCOUNT" && chosen.length > 0) continue;
      chosen.push({ procedure, target });
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

  private targetFor(context: RecommendationContextDto, actionCode: string): string | null {
    const kind = TARGET_KIND[actionCode];
    if (!kind) return null;
    if (kind === "host") return context.affectedHosts[0] ?? null;
    const linked = targetableIocValues(context);
    return context.iocs.find((i) => linked.has(i.iocValue) && IOC_KIND[i.iocType.toLowerCase()] === kind)?.iocValue ?? null;
  }
}
