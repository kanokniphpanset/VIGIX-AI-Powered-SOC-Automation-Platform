import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";
import { RecommendationContextBuilder } from "../services/RecommendationContextBuilder";
import { IRecommendationAgentPort } from "../ports/IRecommendationAgentPort";
import { RecommendationValidator } from "../../../infrastructure/recommendation-validation/RecommendationValidator";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";
import { buildCorrectionPrompt, evidenceValues, MAX_RECOMMENDATION_ATTEMPTS, shouldRetry } from "../services/RecommendationCorrection";
import { isRecommendable, newStepOptions } from "../dto/RecommendationContextDto";

export type GenerateRecommendationError =
  | "INCIDENT_NOT_FOUND"
  | "AI_UNAVAILABLE"
  | "INVALID_AI_OUTPUT"
  | "INSUFFICIENT_EVIDENCE"
  | "NO_NEW_RECOMMENDATION"
  | "DUPLICATE_RECOMMENDATION";

/**
 * GenerateRecommendationUseCase — the ONLY entry point that produces a
 * Recommendation. Orchestrates, in order: build authoritative context ->
 * ask the AI agent for a raw candidate -> validate it deterministically
 * (RecommendationValidator, never trusted before this) -> persist ->
 * supersede any prior recommendation for this incident -> audit.
 *
 * Only a VALIDATED candidate is persisted. AI failure (error/timeout) or an
 * INVALID candidate (schema failure, no usable step) persists nothing,
 * supersedes nothing, and is audited as RECOMMENDATION_GENERATION_FAILED.
 *
 * Response Process Recommendation v2 (Task 10.3): the context carries the
 * backend-selected incident-level Playbook, each allowed Action's own Runbook
 * and the Policy result per Action; the validator rejects the whole candidate
 * on any grounding/policy/Core-Flow violation (no partial repair).
 *
 * Bounded correction (at most ONE retry): when the candidate is INVALID for a reason the model can fix (a mis-copied
 * IOC / target / host, a wrong action or format), the agent is asked once more with ONLY the validator's findings and,
 * for a mis-copied value, the closest exact evidence value. The regenerated candidate goes through the same validator;
 * a second failure is final. Context problems (NO_PLAYBOOK, POLICY_UNAVAILABLE) are never retried. One audit record
 * either way, carrying every attempt's violations.
 *
 * Insufficient evidence (Knowledge Expansion, Step 9): when the selected playbook allows Actions but none of them
 * applies to the attack type with its required evidence recorded (ActionEvidence.ts), the AI is NOT asked — there is
 * nothing it may recommend, and it must never invent an Action to fill the gap. Nothing is persisted; the failure
 * is audited with the missing evidence per Action so the SOC knows what to investigate next.
 *
 * No repeat (new round / regenerate): a Recommendation must add at least one Action + target pair that no earlier
 * Recommendation of the incident proposed (RecommendationValidator NO_NEW_STEP, correctable by the one retry). When the
 * evidence leaves no such pair at all, the AI is not asked (NO_NEW_RECOMMENDATION: add evidence or escalate); when
 * the AI still only repeats after the retry, the failure is DUPLICATE_RECOMMENDATION.
 *
 * RULE-015: builds the context from the Incident's CURRENT
 * investigationNumber on every call — a second call after Verification
 * bumps investigationNumber automatically produces Recommendation #2 from
 * fresh evidence, never a copy of #1's rows.
 */
export class GenerateRecommendationUseCase {
  constructor(
    private readonly contextBuilder: RecommendationContextBuilder,
    private readonly agent: IRecommendationAgentPort,
    private readonly agentVersion: string,
    private readonly validator: RecommendationValidator,
    private readonly recommendationRepository: IRecommendationRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Result<Recommendation, GenerateRecommendationError>> {
    const contextResult = await this.contextBuilder.build(input.incidentId, input.tenantId);
    if (contextResult.isFailure) return Result.fail("INCIDENT_NOT_FOUND");
    const context = contextResult.value;

    const procedures = context.actionProcedures ?? [];
    if (context.playbook && procedures.length > 0 && !procedures.some(isRecommendable)) {
      await this.auditFailure(input, context.investigationNumber, "INSUFFICIENT_EVIDENCE", [], {
        playbook: context.playbook.code,
        attackType: context.attackType ?? null,
        missingEvidence: procedures.map((p) => ({ action: p.actionCode, applicable: p.applicable !== false, missing: p.evidence?.missing ?? [] })),
        nextStep: "ADDITIONAL_INVESTIGATION",
      });
      return Result.fail("INSUFFICIENT_EVIDENCE");
    }

    const previous = context.previousSteps ?? [];
    const options = newStepOptions(context);
    if (context.playbook && previous.length > 0 && options?.length === 0) {
      await this.auditFailure(input, context.investigationNumber, "NO_NEW_RECOMMENDATION", [], {
        playbook: context.playbook.code,
        previousSteps: previous.map((s) => ({ recommendationNumber: s.recommendationNumber, action: s.actionCode, target: s.target })),
        nextStep: "ADDITIONAL_INVESTIGATION_OR_ESCALATE",
      });
      return Result.fail("NO_NEW_RECOMMENDATION");
    }

    // No valid AI result -> nothing is persisted and no earlier recommendation is superseded; only an audit
    // record is written. A Recommendation row always stands for a validated, evidence-grounded AI proposal.
    let rawCandidate: unknown;
    try {
      rawCandidate = await this.agent.generate(context);
    } catch (err) {
      await this.auditFailure(input, context.investigationNumber, "AI_UNAVAILABLE", [err instanceof Error ? err.message : String(err)]);
      return Result.fail("AI_UNAVAILABLE");
    }

    let outcome = await this.validator.validate(rawCandidate, context, input.tenantId);
    let attempts = 1;
    let firstAttemptViolations: string[] = [];
    let correction: string | null = null;
    if (outcome.status !== "VALIDATED" && shouldRetry(outcome.violations) && attempts < MAX_RECOMMENDATION_ATTEMPTS) {
      firstAttemptViolations = outcome.violations;
      correction = buildCorrectionPrompt(outcome.violations, evidenceValues(context));
      attempts++;
      try {
        rawCandidate = await this.agent.generate(context, correction);
        outcome = await this.validator.validate(rawCandidate, context, input.tenantId);
      } catch (err) {
        // The retry itself could not run: the recommendation stays INVALID (the first candidate's findings stand).
        await this.auditFailure(input, context.investigationNumber, "INVALID_AI_OUTPUT", firstAttemptViolations, {
          attempts,
          firstAttemptViolations,
          retryError: err instanceof Error ? err.message : String(err),
        });
        return Result.fail("INVALID_AI_OUTPUT");
      }
    }
    if (outcome.status !== "VALIDATED") {
      // Only repeating earlier pairs is its own failure: the SOC / IR sees "the AI repeated itself", not "invalid output".
      const reason = outcome.violations.every((v) => v.startsWith("NO_NEW_STEP:")) ? "DUPLICATE_RECOMMENDATION" : "INVALID_AI_OUTPUT";
      await this.auditFailure(input, context.investigationNumber, reason, outcome.violations, attempts > 1 ? { attempts, firstAttemptViolations } : undefined);
      return Result.fail(reason);
    }

    const recommendationNumber = await this.recommendationRepository.getNextRecommendationNumber(input.incidentId, input.tenantId);

    const recommendation = await this.recommendationRepository.create({
      tenantId: input.tenantId,
      incidentId: input.incidentId,
      investigationNumber: context.investigationNumber,
      recommendationNumber,
      status: outcome.status,
      summary: outcome.summary,
      createdBy: this.agentVersion,
      steps: outcome.steps,
      snapshot: outcome.snapshot,
    });

    if (recommendationNumber > 1) {
      await this.recommendationRepository.supersedePrevious(input.incidentId, input.tenantId, recommendation.id);
    }

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: this.agentVersion,
      action: "RECOMMENDATION_GENERATED",
      entity: "Recommendation",
      entityId: recommendation.id,
      metadata: {
        incidentId: input.incidentId,
        recommendationNumber,
        investigationNumber: context.investigationNumber,
        status: outcome.status,
        violations: outcome.violations,
        stepCount: outcome.steps.length,
        playbook: context.playbook?.code ?? null,
        snapshotId: recommendation.snapshotId,
        steps: recommendation.steps.map((s) => ({ stepId: s.id, actionId: s.actionId, target: s.target, requiresApproval: s.requiresApproval })),
        // Validated on the first answer (attempts 1) or after the single targeted correction (attempts 2).
        attempts,
        ...(attempts > 1 ? { correctedViolations: firstAttemptViolations, correction } : {}),
      },
    });

    return Result.ok(recommendation);
  }

  private async auditFailure(
    input: { incidentId: string; tenantId: string },
    investigationNumber: number,
    reason: "AI_UNAVAILABLE" | "INVALID_AI_OUTPUT" | "INSUFFICIENT_EVIDENCE" | "NO_NEW_RECOMMENDATION" | "DUPLICATE_RECOMMENDATION",
    violations: string[],
    extra?: Record<string, unknown>
  ): Promise<void> {
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: this.agentVersion,
      action: "RECOMMENDATION_GENERATION_FAILED",
      entity: "Incident",
      entityId: input.incidentId,
      metadata: { incidentId: input.incidentId, investigationNumber, reason, violations, ...(extra ?? {}) },
    });
  }
}
