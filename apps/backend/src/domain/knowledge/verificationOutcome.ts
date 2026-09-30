/**
 * The four verification outcomes the evaluation reports, derived from what CreateVerificationUseCase already
 * records (result + spreadDetected + threatContained). Nothing here decides a result or starts a response:
 * CreateVerificationUseCase derives RESOLVED / NOT_RESOLVED from the re-hunt evidence, and the VERIFICATION
 * policies (RULE-V01..V03) open the next investigation round — whose Recommendation still waits for the IR decision.
 */
export type VerificationOutcome = "RESOLVED" | "NOT_RESOLVED" | "THREAT_SPREAD" | "NOT_CONTAINED";

export const VERIFICATION_OUTCOMES: VerificationOutcome[] = ["RESOLVED", "NOT_RESOLVED", "THREAT_SPREAD", "NOT_CONTAINED"];

/** The VERIFICATION policy that opens a new investigation / recommendation round for each non-resolved outcome. */
export const VERIFICATION_OUTCOME_POLICY: Record<VerificationOutcome, string | null> = {
  RESOLVED: null,
  NOT_RESOLVED: "RULE-V01",
  THREAT_SPREAD: "RULE-V02",
  NOT_CONTAINED: "RULE-V03",
};

/** Spread wins over not-contained, which wins over a plain NOT_RESOLVED (the most severe finding is reported). */
export function classifyVerificationOutcome(v: { result: string; spreadDetected: boolean; threatContained: boolean }): VerificationOutcome {
  if (v.result === "RESOLVED") return "RESOLVED";
  if (v.spreadDetected) return "THREAT_SPREAD";
  if (!v.threatContained) return "NOT_CONTAINED";
  return "NOT_RESOLVED";
}
