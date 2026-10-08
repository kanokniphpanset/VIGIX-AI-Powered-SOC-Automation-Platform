import { PlaybookProvenanceError, PlaybookProvenanceErrorCode } from "../../../domain/playbook/PlaybookRevisionProvenance";
import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";
import { RecommendationContextBuilder } from "../services/RecommendationContextBuilder";
import { IRecommendationAgentPort } from "../ports/IRecommendationAgentPort";
import { RecommendationValidator } from "../../../infrastructure/recommendation-validation/RecommendationValidator";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";
import { buildCorrectionPrompt, evidenceValues, MAX_RECOMMENDATION_ATTEMPTS, shouldRetry } from "../services/RecommendationCorrection";
import { isRecommendable, newStepOptions, noveltyHistory, RecommendationContextDto } from "../dto/RecommendationContextDto";
import { PlaybookRevisionProvenance } from "../../../domain/playbook/PlaybookRevisionProvenance";
import { IRecommendationAuditRepository } from "../../../domain/recommendation/repositories/IRecommendationAuditRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { SubtypeEvaluation, SubtypeRecommendationService } from "../../subtype/SubtypeRecommendationService";
import { ISubtypeNarrator, mapEvaluationToRecommendation } from "../../subtype/SubtypeStepMapper";

/**
 * Subtype-knowledge integration (apps/knowledge/subtype-playbooks). Optional: without it the use case behaves exactly as before.
 *   shadow  - the subtype plan is evaluated and its audit stored; the recommendation the SOC sees is still the legacy one;
 *   enforce - (only for VALID, deployable knowledge) the recommendation steps come from the approved subtype plan; the AI may only phrase
 *             the summary and its answer is reviewed. Never executes anything.
 */
export interface SubtypeIntegration {
  service: SubtypeRecommendationService;
  audits: IRecommendationAuditRepository;
  actions: IActionRepository;
  runbooks: IRunbookRepository;
  narrator?: ISubtypeNarrator;
}

export type GenerateRecommendationError =
  | PlaybookProvenanceErrorCode
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
    private readonly auditLogger: AuditLogger,
    private readonly atomic?: { run<T>(scope: "recommendation", input: { tenantId: string; incidentId: string }, work: () => Promise<T>): Promise<T> },
    private readonly subtype?: SubtypeIntegration
  ) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Result<Recommendation, GenerateRecommendationError>> {
    try {
      return await this.generate(input);
    } catch (error) {
      // Repository/AtomicWorkflow have already rolled back before a semantic failure is returned.
      if (error instanceof PlaybookProvenanceError) return Result.fail(error.code);
      throw error;
    }
  }

  private async generate(input: { incidentId: string; tenantId: string }): Promise<Result<Recommendation, GenerateRecommendationError>> {
    const contextResult = await this.contextBuilder.buildForGeneration(input.incidentId, input.tenantId);
    if (contextResult.isFailure) return Result.fail("INCIDENT_NOT_FOUND");
    const { context, provenance } = contextResult.value;

    // Subtype knowledge: evaluation never breaks the legacy flow - any failure is audited and the legacy path continues.
    let evaluation: SubtypeEvaluation | null = null;
    if (this.subtype) {
      try {
        evaluation = await this.subtype.service.evaluate({ incidentId: input.incidentId, tenantId: input.tenantId, investigationNumber: context.investigationNumber, rehunt: context.rehunt ?? null });
        if (evaluation.requestedMode === "off") evaluation = null;
      } catch (err) {
        await this.auditLogger.record({ tenantId: input.tenantId, actor: this.agentVersion, action: "SUBTYPE_EVALUATION_FAILED", entity: "Incident", entityId: input.incidentId, metadata: { error: err instanceof Error ? err.message : String(err) } });
      }
    }
    if (evaluation && evaluation.effectiveMode === "enforce" && this.subtype) {
      const mapped = await mapEvaluationToRecommendation(evaluation, context, { actions: this.subtype.actions, runbooks: this.subtype.runbooks, tenantId: input.tenantId, narrator: this.subtype.narrator });
      if (mapped.ok) return this.persistSubtype(input, context, provenance, evaluation, mapped);
      evaluation = { ...evaluation, effectiveMode: "shadow", fallbackReason: mapped.reason };
    }
    // A requested subtype replacement must never silently regenerate legacy recommendations.
    // Review, evidence, capability and catalog prerequisites remain mandatory.
    if (this.subtype && (evaluation?.requestedMode === "enforce" || (!evaluation && (process.env.SUBTYPE_KNOWLEDGE_MODE ?? "enforce") === "enforce"))) {
      if (evaluation) await this.saveAudit(input, context, evaluation, null, "ENFORCE_FALLBACK");
      await this.auditFailure(input, context.investigationNumber, "INSUFFICIENT_EVIDENCE", [], {
        nextStep: "REVIEW_SUBTYPE_READINESS",
        reason: evaluation?.fallbackReason ?? "SUBTYPE_EVALUATION_UNAVAILABLE",
      });
      return Result.fail("INSUFFICIENT_EVIDENCE");
    }
    // Investigation-only UNKNOWN_INCIDENT output has no published revision to pin.
    // Report the missing playbook before asking the LLM or attempting an incomplete snapshot.
    if (!context.playbook && !provenance) {
      await this.auditFailure(input, context.investigationNumber, "PLAYBOOK_PROVENANCE_NOT_FOUND", ["NO_PLAYBOOK"], {
        nextStep: "ADDITIONAL_INVESTIGATION_OR_PUBLISH_MATCHING_PLAYBOOK",
      });
      return Result.fail("PLAYBOOK_PROVENANCE_NOT_FOUND");
    }

    const result = await this.legacyPath(input, context, provenance);
    if (evaluation && this.subtype) await this.saveAudit(input, context, evaluation, result.isSuccess ? result.value.id : null, evaluation.requestedMode === "enforce" ? "ENFORCE_FALLBACK" : "SHADOW");
    return result;
  }

  /** Subtype recommendation: deterministic steps from the approved plan, persisted + audited atomically with the supersede. */
  private async persistSubtype(
    input: { incidentId: string; tenantId: string }, context: RecommendationContextDto, provenance: PlaybookRevisionProvenance | null, ev: SubtypeEvaluation,
    mapped: Extract<Awaited<ReturnType<typeof mapEvaluationToRecommendation>>, { ok: true }>
  ): Promise<Result<Recommendation, GenerateRecommendationError>> {
    const persist = async (): Promise<Result<Recommendation, GenerateRecommendationError>> => {
      const recommendationNumber = await this.recommendationRepository.getNextRecommendationNumber(input.incidentId, input.tenantId);
      const recommendation = await this.recommendationRepository.create({
        tenantId: input.tenantId, incidentId: input.incidentId, investigationNumber: context.investigationNumber, recommendationNumber,
        status: "VALIDATED", summary: mapped.summary, createdBy: `${this.agentVersion}+subtype/${ev.kb.version}`, steps: mapped.steps, snapshot: mapped.snapshot, provenance,
      });
      if (recommendation.recommendationNumber > 1) await this.recommendationRepository.supersedePrevious(input.incidentId, input.tenantId, recommendation.id);
      const before = new Set((context.previousSteps ?? []).map((p) => p.target));
      const now = mapped.steps.filter((s) => s.actionId && s.target).map((s) => s.target as string);
      await this.auditLogger.record({
        tenantId: input.tenantId, actor: this.agentVersion, action: "RECOMMENDATION_GENERATED", entity: "Recommendation", entityId: recommendation.id,
        metadata: {
          incidentId: input.incidentId, recommendationNumber: recommendation.recommendationNumber, investigationNumber: context.investigationNumber, status: "VALIDATED",
          path: "SUBTYPE_KNOWLEDGE", knowledgeVersion: ev.kb.version, stepCount: mapped.steps.length, snapshotId: recommendation.snapshotId, llm: mapped.llm,
          steps: recommendation.steps.map((s) => ({ stepId: s.id, actionId: s.actionId, target: s.target, stepType: s.stepType ?? null, requiresApproval: s.requiresApproval })),
          // Tickets cite THIS version; a changed recommendation after Re-hunt is a new recommendation the SOC must review again.
          changedAfterRehunt: !!context.rehunt && now.some((t) => !before.has(t)),
        },
      });
      await this.saveAudit(input, context, ev, recommendation.id, "ENFORCE", mapped.llm);
      return Result.ok(recommendation);
    };
    return this.atomic ? this.atomic.run("recommendation", input, persist) : persist();
  }

  /** Best-effort: an audit-store problem must never lose the recommendation; the audit then falls back to the generic audit log. */
  private async saveAudit(input: { incidentId: string; tenantId: string }, context: RecommendationContextDto, ev: SubtypeEvaluation, recommendationId: string | null, mode: "SHADOW" | "ENFORCE" | "ENFORCE_FALLBACK", llm?: unknown): Promise<void> {
    if (!this.subtype) return;
    const audit = { ...ev.audit, llm: llm ?? null, fallbackReason: ev.fallbackReason, userText: ev.composition?.userText ?? null };
    try {
      await this.subtype.audits.save({ tenantId: input.tenantId, incidentId: input.incidentId, recommendationId, investigationNumber: context.investigationNumber, mode, knowledgeVersion: ev.kb.version, knowledgeStatus: ev.kb.status, audit });
    } catch (err) {
      await this.auditLogger.record({ tenantId: input.tenantId, actor: this.agentVersion, action: "RECOMMENDATION_SUBTYPE_AUDIT", entity: "Incident", entityId: input.incidentId, metadata: { recommendationId, mode, knowledgeVersion: ev.kb.version, storeError: err instanceof Error ? err.message : String(err), audit } });
    }
  }

  private async legacyPath(input: { incidentId: string; tenantId: string }, context: RecommendationContextDto, provenance: PlaybookRevisionProvenance | null): Promise<Result<Recommendation, GenerateRecommendationError>> {
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

    const previous = noveltyHistory(context);
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

    const persist = async (): Promise<Result<Recommendation, GenerateRecommendationError>> => {
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
        provenance,
      });

      if (recommendation.recommendationNumber > 1) {
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
          recommendationNumber: recommendation.recommendationNumber,
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
    };
    // Inference and deterministic validation stay outside the DB transaction.
    return this.atomic ? this.atomic.run("recommendation", input, persist) : persist();
  }

  private async auditFailure(
    input: { incidentId: string; tenantId: string },
    investigationNumber: number,
    reason: "AI_UNAVAILABLE" | "INVALID_AI_OUTPUT" | "INSUFFICIENT_EVIDENCE" | "NO_NEW_RECOMMENDATION" | "DUPLICATE_RECOMMENDATION" | "PLAYBOOK_PROVENANCE_NOT_FOUND",
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
