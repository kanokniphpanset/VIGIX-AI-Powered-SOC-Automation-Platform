import { AiServerUnavailableError, LlmRecommendationAgent } from "../src/infrastructure/ai/LlmRecommendationAgent";
import { OpenRouterRecommendationAgent, parseJsonObject } from "../src/infrastructure/ai/OpenRouterRecommendationAgent";
import { FallbackRecommendationAgent } from "../src/infrastructure/ai/FallbackRecommendationAgent";
import { RecommendationContextDto } from "../src/application/recommendation/dto/RecommendationContextDto";

/** OpenRouter fallback when the AI orchestrator is down. fetch is mocked: nothing leaves the machine. */
const context = {
  incidentId: "inc-1", investigationNumber: 1, incidentTitle: "t", incidentStatus: "investigating", incidentPriority: "high", alertSeverity: "high",
  iocs: [], mitreMappings: [], severity: "HIGH", evidence: [], affectedHosts: [], aiAnalysis: null, availableActions: [], availableRunbooks: [],
  incidentType: null, playbook: null, actionProcedures: [],
} as unknown as RecommendationContextDto;
const ANSWER = { summary: "Isolate the host", steps: [] };
const KEY = "test-key-not-real";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const openRouterOk = () => json(200, { choices: [{ message: { content: "```json\n" + JSON.stringify(ANSWER) + "\n```" } }] });

let fetchMock: jest.SpyInstance;
beforeEach(() => (fetchMock = jest.spyOn(global, "fetch")));
afterEach(() => fetchMock.mockRestore());
const silent = () => {};

describe("LlmRecommendationAgent: 'down' vs other failures", () => {
  it("unreachable / 503 / 504 -> AiServerUnavailableError; 502 (it answered) and 4xx -> plain Error", async () => {
    const agent = new LlmRecommendationAgent("http://orchestrator");
    fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
    await expect(agent.generate(context)).rejects.toBeInstanceOf(AiServerUnavailableError);
    for (const status of [503, 504]) {
      fetchMock.mockResolvedValueOnce(json(status, { error: "LLM_UNAVAILABLE" }));
      await expect(agent.generate(context)).rejects.toBeInstanceOf(AiServerUnavailableError);
    }
    for (const status of [502, 422]) {
      fetchMock.mockResolvedValueOnce(json(status, { error: "x" }));
      const err = await agent.generate(context).catch((e) => e);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(AiServerUnavailableError);
    }
  });
});

describe("OpenRouterRecommendationAgent", () => {
  it("posts the recommendation prompt to OpenRouter chat completions with the key as a Bearer token", async () => {
    fetchMock.mockResolvedValueOnce(openRouterOk());
    const out = await new OpenRouterRecommendationAgent(KEY, "openrouter/auto").generate(context);
    expect(out).toEqual(ANSWER);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://openrouter.ai/api/v1/chat/completions");
    expect(init.headers.Authorization).toBe(`Bearer ${KEY}`);
    const body = JSON.parse(init.body);
    expect(body.model).toBe("openrouter/auto");
    expect(body.response_format).toEqual({ type: "json_object" });
    expect(body.messages[1].content).toContain("Allowed Actions");
  });

  it("an error answer or empty content is an error (never an invented recommendation); no key -> refuses to start", async () => {
    fetchMock.mockResolvedValueOnce(json(401, { error: { message: "No auth" } }));
    await expect(new OpenRouterRecommendationAgent(KEY).generate(context)).rejects.toThrow("OpenRouter responded with 401");
    fetchMock.mockResolvedValueOnce(json(200, { choices: [] }));
    await expect(new OpenRouterRecommendationAgent(KEY).generate(context)).rejects.toThrow("no recommendation content");
    expect(() => new OpenRouterRecommendationAgent("")).toThrow("OPENROUTER_API_KEY");
  });

  it("parses a fenced or wrapped JSON object", () => {
    expect(parseJsonObject('Here you go: {"a":1} thanks')).toEqual({ a: 1 });
    expect(parseJsonObject("```json\n{\"a\":2}\n```")).toEqual({ a: 2 });
    expect(() => parseJsonObject("no json")).toThrow();
  });
});

describe("FallbackRecommendationAgent", () => {
  const agent = () => new FallbackRecommendationAgent(new LlmRecommendationAgent("http://orchestrator"), new OpenRouterRecommendationAgent(KEY), silent);

  it("orchestrator up -> its answer; OpenRouter is not called", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { summary: "from orchestrator", steps: [] }));
    expect(await agent().generate(context)).toEqual({ summary: "from orchestrator", steps: [] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("orchestrator down -> the same request goes to OpenRouter (the correction too)", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("fetch failed")).mockResolvedValueOnce(openRouterOk());
    expect(await agent().generate(context, "Fix: step 1 cites E9")).toEqual(ANSWER);
    expect(fetchMock.mock.calls[1][0]).toBe("https://openrouter.ai/api/v1/chat/completions");
    expect(JSON.parse(fetchMock.mock.calls[1][1].body).messages[1].content).toContain("Fix: step 1 cites E9");
  });

  it("orchestrator answered with an error (not down) -> that error, no fallback", async () => {
    fetchMock.mockResolvedValueOnce(json(502, { error: "INVALID_LLM_OUTPUT" }));
    await expect(agent().generate(context)).rejects.toThrow("responded with 502");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
