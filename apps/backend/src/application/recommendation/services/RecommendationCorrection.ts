import { RecommendationContextDto, targetableIocValues } from "../dto/RecommendationContextDto";

/**
 * One targeted correction round for an INVALID AI recommendation (bounded: at most ONE retry).
 *
 * The retry prompt carries ONLY what the deterministic RecommendationValidator reported, plus — for a value the model
 * mis-copied (e.g. "185.20.101.45" for the evidence value "185.220.101.45") — the closest EXACT value from the
 * supplied evidence. It never asks the model to "think again" or to use anything from memory; the regenerated
 * candidate goes through the same validator, and a second failure is final (FAILED -> SOC review).
 */

/** Violations a second answer cannot fix — they describe the context, not the model's output. No retry for them. */
export const NON_RETRYABLE_VIOLATIONS = ["NO_PLAYBOOK", "POLICY_UNAVAILABLE"] as const;

/** Violations about a VALUE the model wrote that is not in the evidence — these get an "expected" hint when possible. */
const VALUE_VIOLATIONS = ["INVENTED_IOC", "INVENTED_TARGET", "INVENTED_HOST"];

export const MAX_RECOMMENDATION_ATTEMPTS = 2;

const codeOf = (violation: string) => violation.split(":", 1)[0].trim();

export function shouldRetry(violations: string[]): boolean {
  return violations.length > 0 && !violations.some((v) => (NON_RETRYABLE_VIOLATIONS as readonly string[]).includes(codeOf(v)));
}

/** Levenshtein distance (small strings: IPs, hashes, hostnames, domains). */
export function editDistance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** The closest exact evidence value to a mis-copied one, only when it is plausibly the same value (a typo). */
export function closestEvidenceValue(invalid: string, allowed: string[]): string | null {
  let best: { value: string; d: number } | null = null;
  for (const value of allowed) {
    const d = editDistance(invalid.toLowerCase(), value.toLowerCase());
    if (!best || d < best.d) best = { value, d };
  }
  if (!best || best.d === 0) return null;
  const tolerance = Math.max(2, Math.floor(invalid.length * 0.15));
  return best.d <= tolerance ? best.value : null;
}

/** Every exact value the model may write for a target / IOC / host: the evidence it was given. */
export function evidenceValues(context: Pick<RecommendationContextDto, "iocs" | "evidence" | "affectedHosts">): string[] {
  return [...new Set([...context.iocs.map((i) => i.iocValue), ...targetableIocValues(context), ...context.affectedHosts, ...context.evidence.flatMap((e) => e.iocValues)])];
}

export interface CorrectionItem {
  code: string;
  invalid: string;
  expected: string | null;
}

export function correctionItems(violations: string[], allowed: string[]): CorrectionItem[] {
  const items: CorrectionItem[] = [];
  for (const violation of violations) {
    const code = codeOf(violation);
    if (!VALUE_VIOLATIONS.includes(code)) continue;
    // The first quoted value in the validator message is the value the model wrote.
    const invalid = /"([^"]+)"/.exec(violation)?.[1];
    if (!invalid) continue;
    items.push({ code, invalid, expected: closestEvidenceValue(invalid, allowed) });
  }
  return items;
}

const LABEL: Record<string, string> = { INVENTED_IOC: "Invalid IOC", INVENTED_TARGET: "Invalid target", INVENTED_HOST: "Invalid host" };

/** The prompt section appended for the single retry. */
export function buildCorrectionPrompt(violations: string[], allowed: string[]): string {
  const lines = [
    "CORRECTION REQUIRED — the previous response was rejected by the deterministic grounding validator for these reasons:",
    ...violations.map((v) => `- ${v}`),
  ];
  const items = correctionItems(violations, allowed);
  if (items.length) {
    lines.push("", "The previous response contained values that do not exactly match the supplied evidence:");
    for (const i of items) {
      lines.push(i.expected ? `- ${LABEL[i.code] ?? "Invalid value"}: ${i.invalid} -> Expected evidence value: ${i.expected}` : `- ${LABEL[i.code] ?? "Invalid value"}: ${i.invalid} -> not present in the supplied evidence; do not use it`);
    }
  }
  lines.push(
    "",
    "Regenerate the complete response using only exact values from the supplied evidence, copied character for character.",
    "Do not use any value from memory or general knowledge. Keep the same output format."
  );
  return lines.join("\n");
}
