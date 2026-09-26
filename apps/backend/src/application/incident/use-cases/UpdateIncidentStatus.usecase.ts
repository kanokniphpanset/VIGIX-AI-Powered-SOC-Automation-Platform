import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { Incident, IncidentStatus } from "../../../domain/incident/entities/Incident.entity";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";

const VALID_STATUSES: IncidentStatus[] = ["open", "investigating", "resolved", "dismissed", "escalated"];

/**
 * "resolved" is NEVER set manually: an incident is RESOLVED only by the Verification / Wazuh re-hunt flow
 * (Response -> Re-hunt -> NO MATCH -> RESOLVED, CreateVerificationUseCase). False-positive / informational alerts are
 * handled at Alert triage, not by opening an incident and resolving it by hand.
 */
export const VERIFICATION_ONLY_STATUSES: IncidentStatus[] = ["resolved"];

export interface UpdateIncidentStatusInput {
  id: string;
  tenantId: string;
  status: string;
  actor?: string;
}

export class UpdateIncidentStatusUseCase {
  constructor(private readonly incidentRepository: IIncidentRepository, private readonly auditLogger?: AuditLogger) {}

  async execute(
    input: UpdateIncidentStatusInput
  ): Promise<Result<Incident, "NOT_FOUND" | "INVALID_STATUS" | "RESOLVE_REQUIRES_VERIFICATION">> {
    if (!VALID_STATUSES.includes(input.status as IncidentStatus)) {
      return Result.fail("INVALID_STATUS");
    }
    if (VERIFICATION_ONLY_STATUSES.includes(input.status as IncidentStatus)) {
      return Result.fail("RESOLVE_REQUIRES_VERIFICATION");
    }

    const existing = await this.incidentRepository.findById(input.id, input.tenantId);
    if (!existing) {
      return Result.fail("NOT_FOUND");
    }

    const updated = await this.incidentRepository.updateStatus(
      input.id,
      input.tenantId,
      input.status as IncidentStatus
    );
    if (existing.status !== updated.status) {
      await this.auditLogger
        ?.record({
          tenantId: input.tenantId,
          actor: input.actor ?? "unknown",
          action: "INCIDENT_STATUS_CHANGED",
          entity: "Incident",
          entityId: input.id,
          metadata: { from: existing.status, to: updated.status, manual: true },
        })
        .catch((err) => console.error("Failed to audit incident status change", input.id, err instanceof Error ? err.message : err));
    }
    return Result.ok(updated);
  }
}
