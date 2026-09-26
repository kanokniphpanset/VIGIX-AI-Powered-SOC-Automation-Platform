import { IRecommendationAgentPort } from "../../application/recommendation/ports/IRecommendationAgentPort";
import { RecommendationContextDto } from "../../application/recommendation/dto/RecommendationContextDto";
import { RecommendationPromptBuilder } from "./RecommendationPromptBuilder";

/**
 * LlmRecommendationAgent — HTTP adapter to the AI orchestrator
 * (apps/ai-orchestrator, POST /recommendations/generate), NOT a second
 * orchestrator. It only serializes RecommendationContextDto via
 * RecommendationPromptBuilder and posts it; the orchestrator adds RAG
 * grounding and makes the LLM call. Selected in container.ts by
 * RECOMMENDATION_AGENT=llm.
 *
 * Any non-2xx answer (503 LLM_UNAVAILABLE, 504 LLM_TIMEOUT, 502
 * INVALID_LLM_OUTPUT) or a request exceeding `timeoutMs` throws — the
 * caller persists nothing in that case. The returned JSON is UNVALIDATED;
 * RecommendationValidator decides what is usable.
 */
export class LlmRecommendationAgent implements IRecommendationAgentPort {
  constructor(
    private readonly baseUrl: string,
    private readonly promptBuilder: RecommendationPromptBuilder = new RecommendationPromptBuilder(),
    private readonly timeoutMs: number = Number(process.env.RECOMMENDATION_AGENT_TIMEOUT_MS ?? 180_000)
  ) {}

  async generate(context: RecommendationContextDto, correction?: string): Promise<unknown> {
    const base = this.promptBuilder.build(context);
    // Bounded retry: the SAME prompt + only the validator's findings (see RecommendationCorrection).
    const prompt = correction ? `${base}\n\n${correction}` : base;

    const res = await fetch(`${this.baseUrl}/recommendations/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ context, prompt }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`AI orchestrator responded with ${res.status} for recommendation generation: ${detail.slice(0, 500)}`);
    }

    return res.json();
  }
}
