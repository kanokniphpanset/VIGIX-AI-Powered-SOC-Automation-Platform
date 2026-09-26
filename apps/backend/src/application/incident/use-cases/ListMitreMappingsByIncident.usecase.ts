import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { IRecommendationContextRepository, MitreMappingContextRow } from "../../recommendation/ports/IRecommendationContextRepository";
import { Result } from "../../../shared/result/Result";

/** Read-only — reuses the existing IRecommendationContextRepository.getMitreMappings()
 * (already built and wired for Recommendation context assembly) and exposes
 * it for the Ticket Detail "Investigation & Evidence" section. Tenant
 * ownership is checked here since getMitreMappings() itself does not filter by tenant. */
export class ListMitreMappingsByIncidentUseCase {
  constructor(
    private readonly incidentRepository: IIncidentRepository,
    private readonly recommendationContextRepository: IRecommendationContextRepository
  ) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Result<MitreMappingContextRow[], "INCIDENT_NOT_FOUND">> {
    const incident = await this.incidentRepository.findById(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");

    const mappings = await this.recommendationContextRepository.getMitreMappings(input.incidentId);
    return Result.ok(mappings);
  }
}
