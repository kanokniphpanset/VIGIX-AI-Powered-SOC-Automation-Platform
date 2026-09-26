import { z } from "zod";

/**
 * RecommendationCandidateDto — the shape ANY RecommendationAgent
 * implementation (Fake or Llm) must return. This is UNVALIDATED AI output:
 * it references actions/runbooks/playbooks by CODE (never an internal DB id,
 * since the AI is never given one), and every field is re-checked by
 * RecommendationValidator before anything reaches the Recommendation
 * table. Parsing failure here is itself a valid, auditable outcome (RULE-013)
 * — never patched up or guessed at.
 *
 * Response Process Recommendation v2 (Task 10.3): a Recommendation is the
 * action-level expansion of the selected response Action(s) — it does NOT
 * restate the VIGIX Core Flow (Validate → Check → Block → Monitor → Re-hunt
 * is the platform's process, owned by Playbook STC-001 and the workflow
 * itself). Each step is ONE Action with its target and the concrete,
 * ordered operational instructions for the Policy-assigned responsible role.
 * Required per step: action, objective, responsibleRole, target, reason,
 * instructions[], playbook, runbook, verificationCriteria. 1..N steps.
 */
const instructionSchema = z
  .object({
    order: z.number().int().positive(),
    instruction: z.string().trim().min(1),
    target: z.string().nullable().optional(),
    expectedResult: z.string().nullable().optional(),
  })
  .strict();

const candidateStepSchema = z
  .object({
    stepOrder: z.number().int().positive(),
    action: z.string().trim().min(1),
    objective: z.string().trim().min(1),
    responsibleRole: z.string().trim().min(1),
    target: z.string().trim().min(1),
    reason: z.string().trim().min(1),
    evidenceRefs: z.array(z.string()).default([]),
    instructions: z.array(instructionSchema).min(1),
    playbook: z.string().trim().min(1),
    runbook: z.string().trim().min(1),
    verificationCriteria: z.string().trim().min(1),
    expectedResult: z.string().nullable().optional(),
    missingEvidence: z.array(z.string()).default([]),
    confidence: z.number().min(0).max(1).default(0),
    /** Advisory only — omitted means "no opinion". Policy decides; a `false` where Policy requires approval is a bypass attempt. */
    requiresApprovalSuggested: z.boolean().optional(),
  })
  .strict();

export const recommendationCandidateSchema = z
  .object({
    summary: z.string().trim().min(1),
    steps: z.array(candidateStepSchema).min(1),
  })
  .strict();

export type RecommendationCandidateDto = z.infer<typeof recommendationCandidateSchema>;
export type RecommendationCandidateStepDto = z.infer<typeof candidateStepSchema>;
export type RecommendationCandidateInstructionDto = z.infer<typeof instructionSchema>;
