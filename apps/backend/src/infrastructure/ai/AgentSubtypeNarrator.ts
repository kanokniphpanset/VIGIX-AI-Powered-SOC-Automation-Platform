import { IRecommendationAgentPort } from "../../application/recommendation/ports/IRecommendationAgentPort";
import { RecommendationContextDto } from "../../application/recommendation/dto/RecommendationContextDto";
import { ISubtypeNarrator, SubtypeBrief } from "../../application/subtype/SubtypeStepMapper";

/**
 * AgentSubtypeNarrator - lets the existing recommendation agent (Fake / LLM) phrase a one-line summary for an APPROVED plan.
 * The plan is attached to the context as `subtypePlan` (RecommendationPromptBuilder renders a narration-only prompt for it). The answer is
 * returned unvalidated; SubtypeStepMapper reviews it against the plan (reviewCandidate): extra actions, extra targets, new indicators,
 * internal ids, placeholders, secrets or success claims reject it and the deterministic summary is kept. It can never add or widen a step.
 */
export class AgentSubtypeNarrator implements ISubtypeNarrator {
  constructor(private readonly agent: IRecommendationAgentPort) {}

  async narrate(context: RecommendationContextDto, brief: SubtypeBrief): Promise<unknown | null> {
    return this.agent.generate({ ...context, actionProcedures: [], subtypePlan: brief });
  }
}
