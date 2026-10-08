import { RecommendationContextContainmentProcedure, RecommendationContextDto, RecommendationContextTransition } from "../dto/RecommendationContextDto";
import { deriveEvidenceSignals } from "../../../domain/knowledge/evidenceSignals";

type ApplicabilityContext = Pick<RecommendationContextDto, "mitreMappings"> & Partial<Pick<RecommendationContextDto, "evidence" | "iocs" | "incidentTitle">>;

/** The evidence signals this context holds — always re-derived from recorded data, never taken from AI output. */
export function contextSignals(context: ApplicabilityContext): Set<string> {
  return deriveEvidenceSignals({ mitreMappings: context.mitreMappings, evidence: context.evidence, iocs: context.iocs, incidentTitle: context.incidentTitle });
}

/**
 * Knowledge declares the conditions; this shared path never derives facts from AI prose. A step is kept when its
 * MITRE gate (`appliesWhenTechniques`) AND its evidence-signal gate (`appliesWhenSignals`) both hold; decisions of a
 * dropped step are dropped with it. Gating is by what the evidence says, so a response never carries a step for a
 * fact (successful login, executed payload, credential submission, ...) the incident has not established.
 */
export function applicableProcedure(procedure: RecommendationContextContainmentProcedure | null | undefined, context: ApplicabilityContext): RecommendationContextContainmentProcedure | null {
  if (!procedure) return null;
  const techniques = context.mitreMappings.map(m => m.techniqueId);
  const signals = contextSignals(context);
  const steps = procedure.steps
    .filter(s => !s.appliesWhenTechniques?.length || s.appliesWhenTechniques.some(required => techniques.some(t => t === required || t.startsWith(required + "."))))
    .filter(s => !s.appliesWhenSignals?.length || s.appliesWhenSignals.some(signal => signals.has(signal)));
  return { ...procedure, steps, decisions: procedure.decisions.filter(d => steps.some(s => s.stepOrder === d.stepRef)) };
}

/** Branches into another attack type's response opened by the steps that survived gating. */
export function procedureTransitions(procedure: RecommendationContextContainmentProcedure | null | undefined, context: ApplicabilityContext): RecommendationContextTransition[] {
  if (!procedure) return [];
  const signals = contextSignals(context);
  return procedure.steps
    .filter(s => s.escalatesTo)
    .map(s => ({ from: procedure.procedureCode, to: s.escalatesTo!, stepOrder: s.stepOrder, because: (s.appliesWhenSignals ?? []).filter(signal => signals.has(signal)) }));
}
