import { AnalysisSource } from "../../../domain/ai/analysisSource";
import { IRecommendationContextRepository } from "../../recommendation/ports/IRecommendationContextRepository";
import { Result } from "../../../shared/result/Result";

export interface IncidentAiAnalysis {
  /** LlmAnalystAgent output — an automated interpretation, NOT evidence. Null when the pipeline has not produced one. */
  summary: string | null;
  keyFindings: string[];
  /** Post-generation grounding check. UNGROUNDED = the text names indicators absent from the incident's data: shown
   * for review (original text kept), not trusted — it is excluded from the Recommendation context. */
  grounding: { status: "GROUNDED" | "UNGROUNDED"; ungrounded: { kind: string; value: string }[] } | null;
  /** "LLM" when `summary` is a real LLM analysis (with its model and time); null when there is none. */
  source: AnalysisSource | null;
  model: string | null;
  generatedAt: string | null;
  /** Set when the most recent run is NOT the analysis shown (a failed run, or a legacy heuristic fallback that is kept
   * as history but never presented as an AI analysis). */
  latestRun: { source: AnalysisSource; generatedAt: string } | null;
}

/**
 * Read-only view of the AI pipeline's analysis for Incident Detail; same sources the Recommendation context uses.
 * There is no AI severity: the incident severity comes only from the Wazuh rule level (SOC-validated) — never from AI.
 */
export class GetIncidentAiAnalysisUseCase {
  constructor(private readonly context: IRecommendationContextRepository) {}

  async execute(input: { tenantId: string; incidentId: string }): Promise<Result<IncidentAiAnalysis, "INCIDENT_NOT_FOUND">> {
    const incident = await this.context.getIncidentContext(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    const [analysis, run] = await Promise.all([this.context.getLatestAiAnalysis(input.incidentId), this.context.getLatestAnalysisRun?.(input.incidentId) ?? null]);
    const shownAt = analysis?.generatedAt?.getTime() ?? null;
    const latestRun = run && run.generatedAt.getTime() !== shownAt ? { source: run.source, generatedAt: run.generatedAt.toISOString() } : null;
    return Result.ok({
      summary: analysis?.summary ?? null,
      keyFindings: analysis?.keyFindings ?? [],
      grounding: analysis?.grounding ?? null,
      source: analysis?.source ?? null,
      model: analysis?.model ?? null,
      generatedAt: analysis?.generatedAt?.toISOString() ?? null,
      latestRun,
    });
  }
}
