import { RecommendationContextDto } from "../dto/RecommendationContextDto";

/**
 * IRecommendationAgentPort — port (interface) owned by the application
 * layer. Whatever produces candidate recommendation steps (a deterministic
 * fallback today, the AI orchestrator tomorrow) implements this.
 *
 * BOUNDARY (verified before this module was built — see conversation
 * record): an implementation of this port may only turn a
 * RecommendationContextDto into raw candidate JSON. It must NOT perform
 * RAG retrieval, MITRE reasoning, threat-intel reasoning, ML risk scoring,
 * or LangGraph orchestration itself — those, if used at all, belong to the
 * AI orchestrator (apps/ai-orchestrator) and their results would already
 * be reflected in the context (ThreatIntelIoc/MitreMapping rows) built by
 * RecommendationContextBuilder, never recomputed here. The return value is
 * UNVALIDATED — RecommendationValidator (infrastructure/recommendation-
 * validation) is the only component allowed to decide what is actually
 * usable.
 */
export interface IRecommendationAgentPort {
  /**
   * @param correction  set only on the single bounded retry: the validator's own findings for the previous candidate
   *                    (RecommendationCorrection.buildCorrectionPrompt) — never a free "try again".
   */
  generate(context: RecommendationContextDto, correction?: string): Promise<unknown>;
}
