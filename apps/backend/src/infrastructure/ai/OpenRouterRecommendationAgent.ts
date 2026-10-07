import { IRecommendationAgentPort } from "../../application/recommendation/ports/IRecommendationAgentPort";
import { RecommendationContextDto } from "../../application/recommendation/dto/RecommendationContextDto";
import { RecommendationPromptBuilder } from "./RecommendationPromptBuilder";

export const OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1";

/**
 * OpenRouterRecommendationAgent — sends the SAME prompt LlmRecommendationAgent sends to the AI orchestrator
 * (RecommendationPromptBuilder) straight to OpenRouter's chat-completions API, and returns the parsed JSON object.
 * Used as the fallback when the orchestrator is down (FallbackRecommendationAgent). It has no RAG grounding step,
 * but everything it returns still goes through RecommendationValidator (allowed actions, evidence refs, Policy
 * values), so an ungrounded or off-policy answer is rejected exactly like the orchestrator's.
 *
 * The API key comes only from the environment (OPENROUTER_API_KEY) and is never logged or stored.
 */
export class OpenRouterRecommendationAgent implements IRecommendationAgentPort {
  constructor(
    private readonly apiKey: string,
    private readonly model: string = "openrouter/auto",
    private readonly promptBuilder: RecommendationPromptBuilder = new RecommendationPromptBuilder(),
    private readonly timeoutMs: number = Number(process.env.RECOMMENDATION_AGENT_TIMEOUT_MS ?? 180_000),
    private readonly baseUrl: string = OPENROUTER_BASE_URL
  ) {
    if (!apiKey) throw new Error("OPENROUTER_API_KEY is not set");
  }

  async generate(context: RecommendationContextDto, correction?: string): Promise<unknown> {
    const base = this.promptBuilder.build(context);
    const prompt = correction ? `${base}\n\n${correction}` : base;

    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        // Optional OpenRouter attribution headers.
        "X-Title": "VIGIX SOC",
      },
      body: JSON.stringify({
        model: this.model,
        messages: [
          { role: "system", content: "You are the VIGIX response recommendation agent. Answer with ONE JSON object only, no prose, no code fences." },
          { role: "user", content: prompt },
        ],
        response_format: { type: "json_object" },
        temperature: 0.2,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`OpenRouter responded with ${res.status} for recommendation generation: ${detail.slice(0, 500)}`);
    }
    const data = (await res.json()) as { choices?: { message?: { content?: string | null } }[] };
    const content = data.choices?.[0]?.message?.content;
    if (!content) throw new Error("OpenRouter returned no recommendation content");
    return parseJsonObject(content);
  }
}

/** The model's text as a JSON object (tolerates a ```json fence or text around the object). */
export function parseJsonObject(text: string): unknown {
  const unfenced = text.replace(/^\s*```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "");
  try {
    return JSON.parse(unfenced);
  } catch {
    const start = unfenced.indexOf("{");
    const end = unfenced.lastIndexOf("}");
    if (start >= 0 && end > start) return JSON.parse(unfenced.slice(start, end + 1));
    throw new Error("OpenRouter answer is not a JSON object");
  }
}
