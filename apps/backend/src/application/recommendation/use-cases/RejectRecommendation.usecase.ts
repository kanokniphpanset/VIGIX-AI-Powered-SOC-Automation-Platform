import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";
import { Result } from "../../../shared/result/Result";

export type RejectRecommendationError = "RECOMMENDATION_NOT_FOUND" | "RECOMMENDATION_NOT_OPEN" | "ALREADY_SENT_TO_IR" | "INCIDENT_CLOSED" | "NOTE_REQUIRED";

/** Ticket statuses that ended without executing (same set Send to IR treats as replaceable). */
const ENDED_TICKET_STATUSES = new Set(["REJECTED", "FAILED", "CANCELLED", "MORE_EVIDENCE_REQUESTED"]);

/**
 * SOC Validation REJECT — the other exit of "SOC Validation (Validated Recommendation)" in the main flow:
 *   SOC Validation --Accept--> Send to IR        (SendRecommendationToIrUseCase)
 *   SOC Validation --Reject--> Close Incident    (this use case)
 * The SOC decides the incident needs no response: the recommendation is marked REJECTED and the incident is closed
 * (status "dismissed", SLA clocks cancelled). The note is mandatory. Refused once any step of this recommendation already
 * has a live Response Ticket (IR owns it from there). Audited RECOMMENDATION_REJECTED_BY_SOC + INCIDENT_CLOSED.
 */
export class RejectRecommendationUseCase {
  constructor(
    private readonly recommendations: IRecommendationRepository,
    private readonly responsePlans: IResponsePlanRepository,
    private readonly incidents: IIncidentRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { tenantId: string; recommendationId: string; actor: string; note: string | null }): Promise<Result<Recommendation, RejectRecommendationError>> {
    const note = input.note?.trim() || null;
    if (!note) return Result.fail("NOTE_REQUIRED");
    const recommendation = await this.recommendations.findById(input.recommendationId, input.tenantId);
    if (!recommendation) return Result.fail("RECOMMENDATION_NOT_FOUND");
    if (recommendation.status === "SUPERSEDED" || recommendation.status === "REJECTED") return Result.fail("RECOMMENDATION_NOT_OPEN");
    const incident = await this.incidents.findById(recommendation.incidentId, input.tenantId);
    if (!incident) return Result.fail("RECOMMENDATION_NOT_FOUND");
    if (incident.status === "resolved" || incident.status === "dismissed") return Result.fail("INCIDENT_CLOSED");
    const tickets = await this.responsePlans.findByRecommendation(recommendation.id, input.tenantId);
    if (tickets.some((t) => !ENDED_TICKET_STATUSES.has(t.status))) return Result.fail("ALREADY_SENT_TO_IR");

    const rejected = await this.recommendations.updateStatus(recommendation.id, input.tenantId, "REJECTED");
    await this.incidents.updateStatus(incident.id, input.tenantId, "dismissed");

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "RECOMMENDATION_REJECTED_BY_SOC",
      entity: "Recommendation",
      entityId: recommendation.id,
      metadata: { incidentId: incident.id, recommendationNumber: recommendation.recommendationNumber, note },
    });
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "INCIDENT_CLOSED",
      entity: "Incident",
      entityId: incident.id,
      metadata: { from: incident.status, to: "dismissed", reason: "SOC_REJECTED_RECOMMENDATION", recommendationId: recommendation.id, note },
    });

    return Result.ok(rejected);
  }
}
