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
/**
 * The AI server itself is down: unreachable, timed out, or answered 503 / 504. Only this error lets a
 * FallbackRecommendationAgent try another provider; any other failure (e.g. a 4xx) stays an error.
 */
export class AiServerUnavailableError extends Error {
  constructor(message: string, readonly status: number | null = null) {
    super(message);
    this.name = "AiServerUnavailableError";
  }
}

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

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/recommendations/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ context, prompt }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new AiServerUnavailableError(`AI orchestrator unreachable or timed out: ${e instanceof Error ? e.message : String(e)}`);
    }

    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      const message = `AI orchestrator responded with ${res.status} for recommendation generation: ${detail.slice(0, 500)}`;
      // 503 LLM_UNAVAILABLE / 504 LLM_TIMEOUT = no answer available; 502 INVALID_LLM_OUTPUT = it answered (not "down").
      if (res.status === 503 || res.status === 504) throw new AiServerUnavailableError(message, res.status);
      throw new Error(message);
    }

    return res.json();
  }
}
