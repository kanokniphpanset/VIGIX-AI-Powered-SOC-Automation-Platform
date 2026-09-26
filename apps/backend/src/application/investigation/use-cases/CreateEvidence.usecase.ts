import { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { EvidenceRecord, SYSTEM_ONLY_EVIDENCE_TYPES } from "../../../domain/investigation/Investigation.types";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";
import { CreateEvidenceDto } from "../dto/InvestigationDtos";

export type CreateEvidenceFailure =
  | { code: "INVESTIGATION_NOT_FOUND" }
  | { code: "INVESTIGATION_NOT_ACTIVE" }
  | { code: "SYSTEM_EVIDENCE_TYPE"; type: string }
  | { code: "ALERT_NOT_IN_INCIDENT"; alertId: string }
  | { code: "IOC_NOT_IN_INVESTIGATION"; iocIds: string[] };

/**
 * CreateEvidenceUseCase — an analyst records factual supporting data in an Investigation.
 * Manual evidence is always origin=MANUAL (stamped here, not read from the request). The two SYSTEM types
 * (WAZUH_ALERT, WAZUH_EVENT) cannot be created by hand. A related alert must already be grouped into this
 * Investigation's Incident, and related IOCs must belong to this same Investigation - so Alert -> Evidence -> IOC
 * links can only ever be true statements about stored data.
 */
export class CreateEvidenceUseCase {
  constructor(
    private readonly investigations: IInvestigationRepository,
    private readonly incidents: IIncidentRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { tenantId: string; investigationId: string; createdBy: string; body: CreateEvidenceDto }): Promise<Result<EvidenceRecord, CreateEvidenceFailure>> {
    const inv = await this.investigations.findById(input.investigationId, input.tenantId);
    if (!inv) return Result.fail({ code: "INVESTIGATION_NOT_FOUND" });
    if (inv.status !== "ACTIVE") return Result.fail({ code: "INVESTIGATION_NOT_ACTIVE" });

    const b = input.body;
    if (SYSTEM_ONLY_EVIDENCE_TYPES.includes(b.type)) return Result.fail({ code: "SYSTEM_EVIDENCE_TYPE", type: b.type });

    if (b.alertId) {
      const linked = await this.incidents.findLinkedIncidents([b.alertId], input.tenantId);
      if (linked.get(b.alertId) !== inv.incidentId) return Result.fail({ code: "ALERT_NOT_IN_INCIDENT", alertId: b.alertId });
    }

    const iocIds = [...new Set(b.iocIds ?? [])];
    if (iocIds.length > 0) {
      const found = new Set((await this.investigations.findIocsByIds(iocIds, inv.id)).map((i) => i.id));
      const missing = iocIds.filter((id) => !found.has(id));
      if (missing.length > 0) return Result.fail({ code: "IOC_NOT_IN_INVESTIGATION", iocIds: missing });
    }

    const evidence = await this.investigations.createEvidence({
      investigationId: inv.id,
      alertId: b.alertId ?? null,
      type: b.type,
      source: b.source,
      origin: "MANUAL",
      timestamp: b.timestamp ?? new Date(),
      title: b.title,
      description: b.description ?? null,
      rawData: b.rawData ?? null,
      structuredData: b.structuredData ?? null,
      confidence: b.confidence ?? null,
      relevance: b.relevance ?? null,
      createdBy: input.createdBy,
      iocIds,
    });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.createdBy,
      action: "EVIDENCE_CREATED",
      entity: "Evidence",
      entityId: evidence.id,
      metadata: { investigationId: inv.id, incidentId: inv.incidentId, type: b.type, alertId: b.alertId ?? null, iocIds },
    });

    return Result.ok(evidence);
  }
}
