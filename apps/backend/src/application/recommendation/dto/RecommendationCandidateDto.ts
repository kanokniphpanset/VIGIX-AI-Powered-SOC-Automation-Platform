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
 *
 * Attack-specific containment procedures: a step has a `type` —
 *   ACTION  a catalog Action (action, target, runbook required; Policy/approval/evidence enforced; `condition` carries
 *           the procedure's precondition for the Action);
 *   CHECK   an investigation / decision step of the procedure (no catalog action, `procedureStep` required);
 *   MANUAL  a containment control VIGIX cannot execute (no catalog action, `procedureStep` required, never ticketed).
 * `type` defaults to ACTION so a candidate written for the v2 action-only format still parses the same way.
 * The per-type requirements are enforced (with specific violation codes) by RecommendationValidator.
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
    type: z.enum(["ACTION", "CHECK", "MANUAL"]).default("ACTION"),
    action: z.string().trim().min(1).nullable().optional(),
    /** The procedure precondition that must hold before this step is carried out (never dropped for a conditional Action). */
    condition: z.string().trim().min(1).nullable().optional(),
    /** stepOrder of the containment procedure step this step derives from. */
    procedureStep: z.number().int().positive().nullable().optional(),
    objective: z.string().trim().min(1),
    responsibleRole: z.string().trim().min(1),
    target: z.string().trim().min(1).nullable().optional(),
    reason: z.string().trim().min(1),
    evidenceRefs: z.array(z.string()).default([]),
    instructions: z.array(instructionSchema).min(1),
    /** Required for ACTION steps (RecommendationValidator); a CHECK / MANUAL step belongs to the selected playbook anyway. */
    playbook: z.string().trim().min(1).nullable().optional(),
    runbook: z.string().trim().min(1).nullable().optional(),
    verificationCriteria: z.string().trim().min(1),
    expectedResult: z.string().nullable().optional(),
    missingEvidence: z.array(z.string()).default([]),
    confidence: z.number().min(0).max(1).default(0),
    /**
     * Quality contract (all optional, checked by RecommendationValidator — never trusted):
     *  phase          the response phase of the step; must equal the phase of the knowledge step it derives from;
     *  status         how firmly the evidence supports the step: CONFIRMED needs evidence and no open condition,
     *                 CONDITIONAL needs `condition`, POSSIBLE/SUPPORTED are never a claim of fact;
     *  knowledgeRefs  ids of retrieved knowledge the step relies on (UNKNOWN_INCIDENT dynamic steps must cite them);
     *  priority       advisory ordering hint for the analyst.
     */
    phase: z.string().trim().min(1).nullable().optional(),
    status: z.enum(["CONFIRMED", "SUPPORTED", "CONDITIONAL", "POSSIBLE"]).nullable().optional(),
    knowledgeRefs: z.array(z.string()).default([]),
    priority: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).nullable().optional(),
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
