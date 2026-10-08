import { randomBytes } from "node:crypto";
import { Result } from "../../../shared/result/Result";
import { mockExternalAlertId } from "../../../domain/alert/mockAlerts";
import { ISiemAdapter } from "../../../infrastructure/external-services/siem/ISiemAdapter";
import { IMockAlertCatalog } from "../../../infrastructure/mock-alerts/FileMockAlertCatalog";
import { IngestAlertFromSiemUseCase } from "./IngestAlertFromSiem.usecase";

export type SendMockAlertError = "UNKNOWN_MOCK_ALERT" | "INVALID_FIXTURE";

export interface SendMockAlertOutput {
  key: string;
  alertId: string;
  externalAlertId: string;
  severity: string;
  incidentId: string | null;
  triageRequired: boolean;
}

/**
 * Sends one mock fixture (lab / test data) into VIGIX exactly like a Wazuh alert arriving at the webhook: the same
 * Wazuh normalization and the same IngestAlertFromSiemUseCase (severity from the rule level; HIGH / CRITICAL open an
 * incident through Policy INTAKE; MEDIUM waits in the Alert Inbox). Only the alert id and timestamp are replaced — the
 * id with "mock-<key>-…" so the alert is recognisable as mock data and every send is a new alert. Nothing else (no
 * triage, no AI run, no response) is done here. Audited as MOCK_ALERT_SENT with the sender and the fixture file.
 */
export class SendMockAlertUseCase {
  constructor(
    private readonly catalog: IMockAlertCatalog,
    private readonly wazuh: ISiemAdapter,
    private readonly ingest: Pick<IngestAlertFromSiemUseCase, "execute">,
    private readonly audit: { record(entry: { tenantId: string; actor: string; action: string; entity: string; entityId: string; metadata?: Record<string, unknown> }): Promise<unknown> },
    private readonly clock: () => Date = () => new Date()
  ) {}

  async execute(input: { tenantId: string; key: string; actor: string }): Promise<Result<SendMockAlertOutput, SendMockAlertError>> {
    const fixture = this.catalog.find(input.key);
    if (!fixture) return Result.fail("UNKNOWN_MOCK_ALERT");

    const now = this.clock();
    const externalAlertId = mockExternalAlertId(fixture.key, now, randomBytes(3).toString("hex"));
    let normalized;
    try {
      normalized = this.wazuh.normalize({ ...structuredClone(fixture.alert), id: externalAlertId, timestamp: now.toISOString() });
    } catch {
      return Result.fail("INVALID_FIXTURE");
    }

    const result = await this.ingest.execute({ ...normalized, tenantId: input.tenantId });
    const { alert, incidentId, triageRequired } = result.value;
    await this.audit.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "MOCK_ALERT_SENT",
      entity: "Alert",
      entityId: alert.id,
      metadata: { key: fixture.key, file: fixture.file, externalAlertId, severity: alert.severity, incidentId },
    });
    return Result.ok({ key: fixture.key, alertId: alert.id, externalAlertId, severity: alert.severity, incidentId, triageRequired });
  }
}
