import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";

export class ListRecommendationsUseCase {
  constructor(private readonly recommendationRepository: IRecommendationRepository) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Recommendation[]> {
    return this.recommendationRepository.findAllByIncident(input.incidentId, input.tenantId);
  }
}
