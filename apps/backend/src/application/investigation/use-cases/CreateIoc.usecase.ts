import { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { DuplicateIocError, IocRecord } from "../../../domain/investigation/Investigation.types";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";
import { CreateIocDto } from "../dto/InvestigationDtos";
import { checkIocValue } from "../iocValidation";

export type CreateIocFailure =
  | { code: "INVESTIGATION_NOT_FOUND" }
  | { code: "INVESTIGATION_NOT_ACTIVE" }
  | { code: "INVALID_IOC_VALUE"; reason: string }
  | { code: "INVALID_TIME_RANGE" }
  | { code: "DUPLICATE_IOC"; existingIocId: string | null }
  | { code: "SOURCE_ALERT_NOT_FOUND" }
  | { code: "IOC_NOT_IN_SOURCE_ALERT" };

/**
 * CreateIocUseCase — an analyst records an indicator against an Investigation. The value is validated
 * against its declared type and stored in canonical form (hashes / domains lower-cased). The same
 * (type, value) can exist once per Investigation; a later Investigation may record it again on its own.
 *
 * Related-alert evidence (1 Alert = 1 Incident is kept — nothing is grouped or moved): with `sourceAlertId` the SOC
 * records an indicator it observed in ANOTHER Wazuh alert (e.g. the C2 connection of the same malware on the same
 * endpoint). The SOC — not the AI — confirms the relation: a reason is mandatory, and the value must literally appear
 * in that alert's payload, so an indicator can never be attributed to an alert that does not contain it. The re-hunt
 * then hunts for it like any other incident indicator.
 */
export class CreateIocUseCase {
  constructor(
    private readonly investigations: IInvestigationRepository,
    private readonly auditLogger: AuditLogger,
    private readonly alerts?: Pick<IAlertRepository, "findById">
  ) {}

  async execute(input: { tenantId: string; investigationId: string; createdBy: string; body: CreateIocDto }): Promise<Result<IocRecord, CreateIocFailure>> {
    const inv = await this.investigations.findById(input.investigationId, input.tenantId);
    if (!inv) return Result.fail({ code: "INVESTIGATION_NOT_FOUND" });
    if (inv.status !== "ACTIVE") return Result.fail({ code: "INVESTIGATION_NOT_ACTIVE" });

    const b = input.body;
    const checked = checkIocValue(b.iocType, b.iocValue);
    if (!checked.ok) return Result.fail({ code: "INVALID_IOC_VALUE", reason: checked.reason });
    if (b.firstSeen && b.lastSeen && b.firstSeen.getTime() > b.lastSeen.getTime()) return Result.fail({ code: "INVALID_TIME_RANGE" });

    let sourceAlert: { id: string; externalAlertId: string } | null = null;
    if (b.sourceAlertId) {
      const alert = this.alerts ? await this.alerts.findById(b.sourceAlertId, input.tenantId) : null;
      if (!alert) return Result.fail({ code: "SOURCE_ALERT_NOT_FOUND" });
      if (!JSON.stringify(alert.rawPayload ?? {}).toLowerCase().includes(checked.value.toLowerCase())) return Result.fail({ code: "IOC_NOT_IN_SOURCE_ALERT" });
      sourceAlert = { id: alert.id, externalAlertId: alert.externalAlertId };
    }

    let ioc: IocRecord;
    try {
      ioc = await this.investigations.createIoc({
        incidentId: inv.incidentId,
        investigationId: inv.id,
        iocType: b.iocType,
        iocValue: checked.value,
        source: b.source,
        reputationScore: b.reputationScore ?? null,
        confidence: b.confidence ?? null,
        status: b.status ?? "ACTIVE",
        firstSeen: b.firstSeen ?? null,
        lastSeen: b.lastSeen ?? null,
        createdBy: input.createdBy,
        sourceAlertId: sourceAlert?.id ?? null,
        addedReason: sourceAlert ? (b.reason ?? null) : null,
      });
    } catch (err) {
      if (err instanceof DuplicateIocError) return Result.fail({ code: "DUPLICATE_IOC", existingIocId: err.existingIocId });
      throw err;
    }

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.createdBy,
      action: sourceAlert ? "IOC_ADDED_FROM_RELATED_ALERT" : "IOC_CREATED",
      entity: "ThreatIntelIoc",
      entityId: ioc.id,
      metadata: {
        investigationId: inv.id,
        incidentId: inv.incidentId,
        iocType: ioc.iocType,
        iocValue: ioc.iocValue,
        source: ioc.source,
        ...(sourceAlert ? { sourceAlertId: sourceAlert.id, sourceExternalAlertId: sourceAlert.externalAlertId, reason: b.reason, addedBy: input.createdBy } : {}),
      },
    });

    return Result.ok(ioc);
  }
}
