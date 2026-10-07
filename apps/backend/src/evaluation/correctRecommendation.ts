/**
 * correctRecommendation.ts - deterministic "Correct Recommendation" scoring (pure, no DB, no LLM).
 *
 * Question answered: does the recommendation match the predefined Ground Truth for the incident?
 * This is NOT Recommendation Compliance (system/policy validity, EvaluationService.evaluateCompliance) and NOT
 * Core Recommendation Consistency (repeatability). `allowedActions` plays no part here.
 *
 * Rule (fixed before any evaluation run, strict, no optional actions by default):
 *   CORRECT  <=>  playbook matches
 *            AND every expected recommendation (action -> one of its acceptable targets) is present
 *            AND no recommended (action, target) pair falls outside the expected pairs.
 * Steps are compared as a SET of (action, target); order is not part of the rule. Target values are compared
 * case-insensitively after trimming. An expected recommendation may be marked `optional: true` in the Ground Truth;
 * an optional pair is neither required nor unexpected. The Ground Truth for the evaluation marks none.
 */

export interface ExpectedTarget {
  /** TargetKind of the value (the Action Catalog's `targetKind`, domain/knowledge/knowledgeTypes.ts). */
  type: string;
  value: string;
}

export interface ExpectedRecommendation {
  action: string;
  /** Acceptable alternatives for THIS action: one step with this action on any listed target satisfies it. */
  targets: ExpectedTarget[];
  optional?: boolean;
  /** Why this is expected for the scenario (design rationale, never derived from AI output). */
  rationale?: string;
  /** Where the expectation comes from (provenance; never an AI/evaluation output). */
  source?: ExpectedSource;
}

export type ExpectedSource =
  | { kind: "GROUND_TRUTH_EXPECTED_ACTION" }                                    // groundTruthReal.ts expectedActions
  | {                                                                           // prisma/seeds/playbook.seed.ts, unconditional step
      kind: "PLAYBOOK_STANDARD_STEP"; playbook: string; stepOrder: number;
      /** Where the TARGET comes from when it is not already an `expectedTargets` value of groundTruthReal.ts. */
      targetFrom?: { kind: "REAL_WAZUH_SCENARIO"; ruleId: string; field: string };
    };

export interface CorrectnessGroundTruth {
  caseId: string;
  expectedPlaybook: string;
  expectedRecommendations: ExpectedRecommendation[];
}

export interface RecommendedStep {
  action: string;
  target: string;
  /** Kind of the target as defined by the Action Catalog for this action; compared only when supplied. */
  targetType?: string | null;
}

export interface CorrectnessInput {
  playbook: string | null;
  steps: RecommendedStep[];
}

export interface PairRef { action: string; target: string }

export interface CorrectnessResult {
  caseId: string;
  correct: boolean;
  playbookMatch: boolean;
  actionTargetMatches: boolean;
  missingRecommendations: { action: string; acceptableTargets: string[] }[];
  unexpectedRecommendations: PairRef[];
  mismatchedTargets: { action: string; expected: string[]; actual: string }[];
  matchedRecommendations: PairRef[];
  reason: string;
}

const norm = (s: string | null | undefined) => (s ?? "").trim().toLowerCase();

export function evaluateCorrectRecommendation(gt: CorrectnessGroundTruth, rec: CorrectnessInput): CorrectnessResult {
  const playbookMatch = !!rec.playbook && rec.playbook === gt.expectedPlaybook;

  // distinct recommended pairs (a repeated identical pair is one recommendation)
  const seen = new Set<string>();
  const actual = rec.steps.filter((s) => {
    const k = `${s.action}|${norm(s.target)}|${norm(s.targetType)}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const typeOk = (t: ExpectedTarget, s: RecommendedStep) => !s.targetType || norm(s.targetType) === norm(t.type);
  const isExpectedPair = (er: ExpectedRecommendation, s: RecommendedStep) =>
    s.action === er.action && er.targets.some((t) => norm(t.value) === norm(s.target) && typeOk(t, s));

  const matched: PairRef[] = [];
  const missing: CorrectnessResult["missingRecommendations"] = [];
  const mismatched: CorrectnessResult["mismatchedTargets"] = [];
  const covered = new Set<RecommendedStep>();

  for (const er of gt.expectedRecommendations) {
    const hits = actual.filter((s) => isExpectedPair(er, s));
    hits.forEach((h) => { covered.add(h); matched.push({ action: h.action, target: h.target }); });
    if (hits.length === 0 && !er.optional) {
      missing.push({ action: er.action, acceptableTargets: er.targets.map((t) => t.value) });
      for (const s of actual.filter((x) => x.action === er.action)) {
        mismatched.push({ action: er.action, expected: er.targets.map((t) => t.value), actual: s.target });
      }
    }
  }

  const unexpected: PairRef[] = actual
    .filter((s) => !covered.has(s) && !gt.expectedRecommendations.some((er) => er.optional && isExpectedPair(er, s)))
    .map((s) => ({ action: s.action, target: s.target }));

  const actionTargetMatches = missing.length === 0 && unexpected.length === 0;
  const correct = playbookMatch && actionTargetMatches;

  const reasons: string[] = [];
  if (!playbookMatch) reasons.push(`playbook ${rec.playbook ?? "none"} != expected ${gt.expectedPlaybook}`);
  if (missing.length) reasons.push(`missing: ${missing.map((m) => `${m.action} -> ${m.acceptableTargets.join(" | ")}`).join("; ")}`);
  if (unexpected.length) reasons.push(`unexpected: ${unexpected.map((u) => `${u.action} -> ${u.target}`).join("; ")}`);
  return {
    caseId: gt.caseId, correct, playbookMatch, actionTargetMatches,
    missingRecommendations: missing, unexpectedRecommendations: unexpected, mismatchedTargets: mismatched,
    matchedRecommendations: matched,
    reason: correct ? "playbook and all expected action->target pairs match; no unexpected pair" : reasons.join(" | "),
  };
}

export interface CorrectnessAggregate {
  nEvaluated: number;
  nCorrect: number;
  ratePct: number | null;
  correctCases: string[];
  incorrectCases: string[];
  notEvaluable: string[];
}

/** CR = N_correct / N_evaluated x 100. `null` results (no Ground Truth / no recommendation) are NOT evaluable and leave the denominator. */
export function aggregateCorrectness(results: { caseId: string; result: CorrectnessResult | null }[]): CorrectnessAggregate {
  const ev = results.filter((r) => r.result);
  const correct = ev.filter((r) => r.result!.correct);
  return {
    nEvaluated: ev.length,
    nCorrect: correct.length,
    ratePct: ev.length ? Math.round((correct.length / ev.length) * 10000) / 100 : null,
    correctCases: correct.map((r) => r.caseId),
    incorrectCases: ev.filter((r) => !r.result!.correct).map((r) => r.caseId),
    notEvaluable: results.filter((r) => !r.result).map((r) => r.caseId),
  };
}
