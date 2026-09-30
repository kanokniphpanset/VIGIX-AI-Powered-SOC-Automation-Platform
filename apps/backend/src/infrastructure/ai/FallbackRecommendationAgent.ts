import { IRecommendationAgentPort } from "../../application/recommendation/ports/IRecommendationAgentPort";
import { RecommendationContextDto } from "../../application/recommendation/dto/RecommendationContextDto";
import { AiServerUnavailableError } from "./LlmRecommendationAgent";

/**
 * FallbackRecommendationAgent — the AI orchestrator first; only when it is DOWN (AiServerUnavailableError:
 * unreachable, timed out, 503 / 504) the same request goes to the fallback provider (OpenRouter). Any other error of
 * the primary is rethrown unchanged, so a real failure is never hidden behind a second provider.
 */
export class FallbackRecommendationAgent implements IRecommendationAgentPort {
  constructor(
    private readonly primary: IRecommendationAgentPort,
    private readonly fallback: IRecommendationAgentPort,
    private readonly log: (message: string) => void = (m) => console.warn(m)
  ) {}

  async generate(context: RecommendationContextDto, correction?: string): Promise<unknown> {
    try {
      return await this.primary.generate(context, correction);
    } catch (e) {
      if (!(e instanceof AiServerUnavailableError)) throw e;
      this.log(`[recommendation] AI orchestrator unavailable (${e.message.slice(0, 200)}); falling back to OpenRouter for incident ${context.incidentId}`);
      return this.fallback.generate(context, correction);
    }
  }
}
