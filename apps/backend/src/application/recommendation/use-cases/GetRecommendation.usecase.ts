import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";
import { Result } from "../../../shared/result/Result";

export class GetRecommendationUseCase {
  constructor(private readonly recommendationRepository: IRecommendationRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Recommendation, "NOT_FOUND">> {
    const recommendation = await this.recommendationRepository.findById(input.id, input.tenantId);
    if (!recommendation) return Result.fail("NOT_FOUND");
    return Result.ok(recommendation);
  }
}
