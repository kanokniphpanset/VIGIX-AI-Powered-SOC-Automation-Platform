import { classifyAnalysisSource, isTrustedAnalysisSource } from "../src/domain/ai/analysisSource";
import { GetIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { IRecommendationContextRepository } from "../src/application/recommendation/ports/IRecommendationContextRepository";

/**
 * E2E 2026-09-26: every stored "AI analysis" before the fix was the orchestrator's heuristic template (a settings-import
 * bug made each LLM call fail silently). History is kept — rows are classified on read, never modified or deleted —
 * and only real LLM output is shown as the AI Analysis or used as Recommendation context.
 */
describe("AI analysis source (historical data kept, only real LLM output trusted)", () => {
  it("classifies recorded sources and legacy rows", () => {
    expect(classifyAnalysisSource({ analysis_source: "LLM", llm_summary: "Brute force from 185.220.101.45 …" })).toBe("LLM");
    expect(classifyAnalysisSource({ analysis_source: "FAILED", llm_summary: null })).toBe("FAILED");
    expect(classifyAnalysisSource({ llm_summary: "Alert severity: medium. Repeated authentication failures may indicate brute-force activity. 2 evidence-backed finding(s) were identified." })).toBe("HEURISTIC_FALLBACK");
    expect(classifyAnalysisSource({ llm_summary: "Alert severity: low. Repeated authentication failures may indicate brute-force activity. ML risk score is 25.0/100." })).toBe("HEURISTIC_FALLBACK");
    expect(classifyAnalysisSource({ llm_summary: "The host WKS-DEV-12 shows repeated failed root logins." })).toBe("UNVERIFIED_LEGACY");
    expect(classifyAnalysisSource({ llm_summary: "" })).toBe("FAILED");
    expect(classifyAnalysisSource(null)).toBe("FAILED");
  });

  it("only LLM output is trusted", () => {
    expect(["LLM", "FAILED", "HEURISTIC_FALLBACK", "UNVERIFIED_LEGACY"].filter((s) => isTrustedAnalysisSource(s as never))).toEqual(["LLM"]);
  });

  const repo = (over: Partial<IRecommendationContextRepository>): IRecommendationContextRepository =>
    ({
      getIncidentContext: async () => ({ incidentId: "i1", investigationNumber: 1, title: "t", status: "investigating", priority: "medium", alertSeverity: "medium" }),
      getLatestAiAnalysis: async () => null,
      ...over,
    }) as unknown as IRecommendationContextRepository;

  it("API: a legacy heuristic fallback is not shown as an analysis, but its existence is reported", async () => {
    const out = await new GetIncidentAiAnalysisUseCase(
      repo({ getLatestAnalysisRun: async () => ({ source: "HEURISTIC_FALLBACK", generatedAt: new Date("2026-09-20T10:00:00Z") }) })
    ).execute({ tenantId: "t", incidentId: "i1" });
    expect(out.isSuccess && out.value).toMatchObject({ summary: null, source: null, latestRun: { source: "HEURISTIC_FALLBACK", generatedAt: "2026-09-20T10:00:00.000Z" } });
  });

  it("API: the LLM analysis is shown with its model and time; a newer FAILED run is reported next to it", async () => {
    const at = new Date("2026-09-26T08:00:00Z");
    const out = await new GetIncidentAiAnalysisUseCase(
      repo({
        getLatestAiAnalysis: async () => ({ summary: "Grounded LLM analysis.", keyFindings: [], grounding: { status: "GROUNDED", ungrounded: [] }, source: "LLM", model: "gemma4-26b", generatedAt: at }),
        getLatestAnalysisRun: async () => ({ source: "FAILED", generatedAt: new Date("2026-09-26T09:00:00Z") }),
      })
    ).execute({ tenantId: "t", incidentId: "i1" });
    expect(out.isSuccess && out.value).toMatchObject({ summary: "Grounded LLM analysis.", source: "LLM", model: "gemma4-26b", generatedAt: at.toISOString(), latestRun: { source: "FAILED" } });
  });

  it("API: when the shown analysis IS the latest run, no separate latestRun is reported", async () => {
    const at = new Date("2026-09-26T08:00:00Z");
    const out = await new GetIncidentAiAnalysisUseCase(
      repo({
        getLatestAiAnalysis: async () => ({ summary: "x", keyFindings: [], grounding: { status: "GROUNDED", ungrounded: [] }, source: "LLM", model: "m", generatedAt: at }),
        getLatestAnalysisRun: async () => ({ source: "LLM", generatedAt: at }),
      })
    ).execute({ tenantId: "t", incidentId: "i1" });
    expect(out.isSuccess && out.value.latestRun).toBeNull();
  });
});
