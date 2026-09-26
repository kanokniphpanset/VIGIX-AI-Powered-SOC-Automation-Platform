/**
 * Where a stored AI analysis (agent_results, agent llm_analyst) came from. Historical rows are never modified or
 * deleted — they are classified when read, so the UI and the Recommendation context only use real LLM output:
 *
 *   LLM                  recorded by the orchestrator (analysis_source = "LLM", with the model) — shown, trusted
 *   FAILED               the LLM call failed; no analysis text (analysis_source = "FAILED")
 *   HEURISTIC_FALLBACK   legacy row whose text is the orchestrator's deterministic template ("Alert severity: x. …"),
 *                        produced while a settings-import bug made every LLM call fail (fixed 2026-09-26) — kept as
 *                        history, never shown or used as an AI analysis
 *   UNVERIFIED_LEGACY    legacy row with other text and no recorded source — shown only with that label, not trusted
 */
export type AnalysisSource = "LLM" | "FAILED" | "HEURISTIC_FALLBACK" | "UNVERIFIED_LEGACY";

/** The heuristic template always opens with the Wazuh severity sentence (llm_analyst_agent._heuristic_analysis). */
const HEURISTIC_TEMPLATE = /^\s*Alert severity: [a-z]+\.\s/i;

export function classifyAnalysisSource(output: { analysis_source?: unknown; llm_summary?: unknown } | null | undefined): AnalysisSource {
  const recorded = output?.analysis_source;
  if (recorded === "LLM") return "LLM";
  if (recorded === "FAILED") return "FAILED";
  const summary = typeof output?.llm_summary === "string" ? output.llm_summary : "";
  if (!summary.trim()) return "FAILED";
  return HEURISTIC_TEMPLATE.test(summary) ? "HEURISTIC_FALLBACK" : "UNVERIFIED_LEGACY";
}

/** Only real LLM output is shown as the AI Analysis and used as Recommendation context. */
export const isTrustedAnalysisSource = (source: AnalysisSource) => source === "LLM";
