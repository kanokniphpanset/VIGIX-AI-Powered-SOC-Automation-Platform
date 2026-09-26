import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";

export interface ValidateRecommendationOutput {
  recommendation: Recommendation;
  violations: string[];
}

/**
 * ValidateRecommendationUseCase — re-checks an ALREADY-PERSISTED
 * Recommendation's steps against the CURRENT state of the Action/Runbook
 * catalogs (RULE-003/004/012). Generation-time validation
 * (RecommendationValidator) already ran once inside GenerateRecommendation;
 * this endpoint exists because catalog state can change AFTER generation —
 * an Action referenced by an approved step could be disabled, or a Runbook
 * deprecated, before a human acts on the recommendation. If that happened,
 * this flips the Recommendation's status to INVALID rather than leaving a
 * stale VALIDATED status that no longer reflects reality.
 */
export class ValidateRecommendationUseCase {
  constructor(
    private readonly recommendationRepository: IRecommendationRepository,
    private readonly actionRepository: IActionRepository,
    private readonly runbookRepository: IRunbookRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<ValidateRecommendationOutput, "NOT_FOUND">> {
    const recommendation = await this.recommendationRepository.findById(input.id, input.tenantId);
    if (!recommendation) return Result.fail("NOT_FOUND");

    const violations: string[] = [];

    for (const step of recommendation.steps) {
      if (step.actionId) {
        const action = await this.actionRepository.findById(step.actionId, input.tenantId);
        if (!action) {
          violations.push(`Step "${step.title}": referenced action no longer exists`);
        } else if (!action.enabled) {
          violations.push(`Step "${step.title}": referenced action "${action.code}" has been disabled since generation`);
        }
      }
      if (step.sourceRunbookId) {
        const runbook = await this.runbookRepository.findById(step.sourceRunbookId, input.tenantId);
        if (!runbook) {
          violations.push(`Step "${step.title}": referenced runbook no longer exists`);
        } else if (!runbook.isActive) {
          violations.push(`Step "${step.title}": referenced runbook "${runbook.code}" is no longer ACTIVE`);
        }
      }
    }

    let result = recommendation;
    if (violations.length > 0 && recommendation.status === "VALIDATED") {
      result = await this.recommendationRepository.updateStatus(recommendation.id, input.tenantId, "INVALID");
    }

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: "system",
      action: "RECOMMENDATION_VALIDATION_RESULT",
      entity: "Recommendation",
      entityId: recommendation.id,
      metadata: { violations, resultingStatus: result.status },
    });

    return Result.ok({ recommendation: result, violations });
  }
}
