/**
 * containmentRubric.ts - deterministic 7-criterion rubric for an attack-specific containment recommendation
 * (pure, no DB, no LLM). It ADDS to the existing metrics (Recommendation Compliance, Correct Recommendation,
 * Consistency) and replaces none of them.
 *
 * It judges structure and grounding, never wording: which procedure was used, which step types appear, whether every
 * ACTION is a procedure candidate with its condition, evidence and Policy approval, whether the expected Action ->
 * target pairs (Correct Recommendation Ground Truth) are present, and whether verification is covered. A criterion
 * that needs data the input does not have (no Ground Truth -> target correctness) is NOT_EVALUABLE, never a pass.
 *
 *   1 ATTACK_ALIGNMENT          the attack type's own procedure and the expected playbook were used
 *   2 EVIDENCE_SUPPORT          the recommendation validated and every ACTION cites recorded evidence
 *   3 ACTION_COMPLETENESS       at least one CHECK and one ACTION, and no expected Ground Truth pair is missing
 *   4 TARGET_CORRECTNESS        every ACTION with a Ground Truth expectation targets an acceptable value
 *   5 POLICY_COMPLIANCE         validated, approval equals Policy per ACTION, and procedure conditions are carried
 *   6 PLAYBOOK_ALIGNMENT        every step maps to a procedure step holding an item of its type, in procedure order
 *   7 VERIFICATION_COMPLETENESS every step has verification criteria, the procedure has success criteria, and a
 *                               CHECK step comes from the procedure's VERIFY step
 */
import { RecommendationContextContainmentProcedure } from "../application/recommendation/dto/RecommendationContextDto";
import { CorrectnessGroundTruth, evaluateCorrectRecommendation } from "./correctRecommendation";

export type RubricCriterion =
  | "ATTACK_ALIGNMENT"
  | "EVIDENCE_SUPPORT"
  | "ACTION_COMPLETENESS"
  | "TARGET_CORRECTNESS"
  | "POLICY_COMPLIANCE"
  | "PLAYBOOK_ALIGNMENT"
  | "VERIFICATION_COMPLETENESS";

export const RUBRIC_CRITERIA: RubricCriterion[] = [
  "ATTACK_ALIGNMENT",
  "EVIDENCE_SUPPORT",
  "ACTION_COMPLETENESS",
  "TARGET_CORRECTNESS",
  "POLICY_COMPLIANCE",
  "PLAYBOOK_ALIGNMENT",
  "VERIFICATION_COMPLETENESS",
];

export interface RubricStep {
  stepType: "ACTION" | "CHECK" | "MANUAL";
  /** Action code (ACTION steps only). */
  action: string | null;
  target: string | null;
  /** Persisted title; CHECK / MANUAL titles end with the procedure step title ("Check — <title>"). */
  title: string;
  precondition: string | null;
  evidence: string[];
  requiresApproval: boolean;
  verificationCriteria: string | null;
}

export interface RubricInput {
  caseId: string;
  expectedAttackType: string;
  expectedPlaybook: string;
  status: "VALIDATED" | "INVALID";
  playbook: string | null;
  procedure: RecommendationContextContainmentProcedure | null;
  /** Policy approval per Action code (RecommendationContext actionProcedures[].policy). */
  policyApproval: Record<string, boolean>;
  steps: RubricStep[];
  /** Correct Recommendation Ground Truth with environment facts already resolved; null -> TARGET_CORRECTNESS not evaluable. */
  groundTruth?: CorrectnessGroundTruth | null;
}

export interface RubricCriterionResult {
  criterion: RubricCriterion;
  result: "PASS" | "FAIL" | "NOT_EVALUABLE";
  reason: string;
}

export interface RubricResult {
  caseId: string;
  criteria: RubricCriterionResult[];
  passed: number;
  evaluable: number;
  /** passed / evaluable x 100, two decimals; null when nothing is evaluable. */
  scorePct: number | null;
}

/** Procedure step a recommendation step derives from (ACTION: the step listing the Action; CHECK/MANUAL: by title). */
function sourceStep(procedure: RecommendationContextContainmentProcedure, step: RubricStep) {
  if (step.stepType === "ACTION") return procedure.steps.find((s) => s.items.some((i) => i.actionCode === step.action)) ?? null;
  return procedure.steps.find((s) => step.title.endsWith(`— ${s.title}`) && s.items.some((i) => i.type === step.stepType)) ?? null;
}

export function evaluateContainmentRubric(input: RubricInput): RubricResult {
  const r: RubricCriterionResult[] = [];
  const add = (criterion: RubricCriterion, ok: boolean | null, reason: string) =>
    r.push({ criterion, result: ok === null ? "NOT_EVALUABLE" : ok ? "PASS" : "FAIL", reason });
  const { procedure, steps } = input;
  const actions = steps.filter((s) => s.stepType === "ACTION");
  const validated = input.status === "VALIDATED";

  // 1 Attack alignment
  const procOk = procedure?.procedureCode === input.expectedAttackType;
  const pbOk = input.playbook === input.expectedPlaybook;
  add("ATTACK_ALIGNMENT", procOk && pbOk, procOk && pbOk
    ? `procedure ${procedure!.procedureCode} and playbook ${input.playbook} match the attack type`
    : `procedure ${procedure?.procedureCode ?? "none"} (expected ${input.expectedAttackType}), playbook ${input.playbook ?? "none"} (expected ${input.expectedPlaybook})`);

  // 2 Evidence support
  const unsupported = actions.filter((s) => s.evidence.length === 0).map((s) => s.action);
  add("EVIDENCE_SUPPORT", validated && actions.length > 0 && unsupported.length === 0,
    !validated ? "recommendation did not validate" : unsupported.length ? `ACTION without evidence: ${unsupported.join(", ")}` : `${actions.length} ACTION step(s), each citing recorded evidence`);

  // 3 Action completeness + 4 Target correctness (Ground Truth pairs)
  const hasCheck = steps.some((s) => s.stepType === "CHECK");
  const gt = input.groundTruth ?? null;
  const correctness = gt ? evaluateCorrectRecommendation(gt, { playbook: input.playbook, steps: actions.map((s) => ({ action: s.action!, target: s.target ?? "" })) }) : null;
  const missing = correctness?.missingRecommendations ?? [];
  add("ACTION_COMPLETENESS", hasCheck && actions.length > 0 && missing.length === 0,
    !hasCheck || actions.length === 0
      ? `needs CHECK and ACTION steps (CHECK=${steps.filter((s) => s.stepType === "CHECK").length}, ACTION=${actions.length})`
      : missing.length ? `missing expected: ${missing.map((m) => `${m.action} -> ${m.acceptableTargets.join(" | ")}`).join("; ")}` : gt ? "every expected Action -> target pair is present" : "CHECK and ACTION steps present (no Ground Truth pairs to compare)");
  if (!gt) add("TARGET_CORRECTNESS", null, "no Ground Truth for this case");
  else {
    const expectedActions = new Set(gt.expectedRecommendations.map((e) => e.action));
    const judged = actions.filter((s) => expectedActions.has(s.action!));
    const wrong = correctness!.mismatchedTargets;
    add("TARGET_CORRECTNESS", judged.length === 0 ? null : wrong.length === 0,
      judged.length === 0 ? "no recommended Action has a Ground Truth expectation" : wrong.length ? `wrong target: ${wrong.map((w) => `${w.action} -> ${w.actual} (expected ${w.expected.join(" | ")})`).join("; ")}` : `${judged.length} ACTION target(s) match the Ground Truth`);
  }

  // 5 Policy compliance
  const approvalMismatch = actions.filter((s) => s.action! in input.policyApproval && input.policyApproval[s.action!] !== s.requiresApproval).map((s) => s.action);
  const conditionDropped = procedure
    ? actions.filter((s) => procedure.candidateActions.find((c) => c.actionCode === s.action)?.condition && !s.precondition).map((s) => s.action)
    : [];
  add("POLICY_COMPLIANCE", validated && approvalMismatch.length === 0 && conditionDropped.length === 0,
    !validated ? "recommendation did not validate" : approvalMismatch.length ? `approval differs from Policy: ${approvalMismatch.join(", ")}` : conditionDropped.length ? `condition dropped: ${conditionDropped.join(", ")}` : "approval equals Policy and every procedure condition is carried");

  // 6 Playbook / procedure alignment
  if (!procedure) add("PLAYBOOK_ALIGNMENT", false, "no containment procedure in the context");
  else {
    const notCandidate = actions.filter((s) => !procedure.candidateActions.some((c) => c.actionCode === s.action)).map((s) => s.action);
    const sources = steps.map((s) => sourceStep(procedure, s));
    const unmapped = steps.filter((_, i) => !sources[i]).map((s) => `${s.stepType} "${s.title}"`);
    const orders = sources.filter((s): s is NonNullable<typeof s> => !!s).map((s) => s.stepOrder);
    const inOrder = orders.every((o, i) => i === 0 || o >= orders[i - 1]);
    add("PLAYBOOK_ALIGNMENT", notCandidate.length === 0 && unmapped.length === 0 && inOrder,
      notCandidate.length ? `not a procedure candidate: ${notCandidate.join(", ")}` : unmapped.length ? `not grounded in the procedure: ${unmapped.join("; ")}` : !inOrder ? `steps out of procedure order (${orders.join(" -> ")})` : `every step maps to procedure steps ${[...new Set(orders)].join(", ")} in order`);
  }

  // 7 Verification completeness
  const noCriteria = steps.filter((s) => !s.verificationCriteria?.trim()).length;
  const verifyStep = procedure?.steps.find((s) => s.phase === "VERIFY") ?? null;
  const verifyCheck = !!verifyStep && steps.some((s) => s.stepType === "CHECK" && s.title.endsWith(`— ${verifyStep.title}`));
  const successCriteria = procedure?.verification.successCriteria.length ?? 0;
  add("VERIFICATION_COMPLETENESS", noCriteria === 0 && successCriteria > 0 && verifyCheck,
    noCriteria ? `${noCriteria} step(s) without verification criteria` : !successCriteria ? "procedure has no success criteria" : !verifyCheck ? "no CHECK step from the procedure's VERIFY step" : `verification covered (${successCriteria} success criteria)`);

  const evaluable = r.filter((x) => x.result !== "NOT_EVALUABLE").length;
  const passed = r.filter((x) => x.result === "PASS").length;
  return { caseId: input.caseId, criteria: r, passed, evaluable, scorePct: evaluable ? Math.round((passed / evaluable) * 10000) / 100 : null };
}
