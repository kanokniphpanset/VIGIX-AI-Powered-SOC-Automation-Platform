import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { IRecommendationContextRepository, IocContextRow } from "../../recommendation/ports/IRecommendationContextRepository";
import { IThreatIntelVerdictReader, ThreatIntelVerdict } from "../ports/IThreatIntelVerdictReader";
import { Result } from "../../../shared/result/Result";

export type IocWithThreatIntel = IocContextRow & { threatIntel: ThreatIntelVerdict | null };

const key = (type: string, value: string) => `${type.toUpperCase()}|${value.trim().toLowerCase()}`;

/** Read-only — reuses the existing IRecommendationContextRepository.getIocs()
 * (already built and wired for Recommendation context assembly) and exposes
 * it for the Ticket Detail "Investigation & Evidence" section. Tenant
 * ownership is checked here since getIocs() itself does not filter by tenant.
 * Each IOC also carries the Threat Intelligence verdict the AI pipeline already recorded for it (display only;
 * getIocs() and the recommendation context are unchanged). */
export class ListIocsByIncidentUseCase {
  constructor(
    private readonly incidentRepository: IIncidentRepository,
    private readonly recommendationContextRepository: IRecommendationContextRepository,
    private readonly threatIntel?: IThreatIntelVerdictReader
  ) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Result<IocWithThreatIntel[], "INCIDENT_NOT_FOUND">> {
    const incident = await this.incidentRepository.findById(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");

    const [iocs, verdicts] = await Promise.all([
      this.recommendationContextRepository.getIocs(input.incidentId),
      this.threatIntel ? this.threatIntel.latestVerdicts(input.incidentId).catch(() => [] as ThreatIntelVerdict[]) : Promise.resolve([] as ThreatIntelVerdict[]),
    ]);
    const byKey = new Map(verdicts.map((v) => [key(v.iocType, v.iocValue), v]));
    return Result.ok(iocs.map((i) => ({ ...i, threatIntel: byKey.get(key(i.iocType, i.iocValue)) ?? null })));
  }
}
