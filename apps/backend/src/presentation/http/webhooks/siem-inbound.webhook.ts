import { Request, Response } from "express";
import { IngestAlertFromSiemUseCase } from "../../../application/alert/use-cases/IngestAlertFromSiem.usecase";
import { ISiemAdapter } from "../../../infrastructure/external-services/siem/ISiemAdapter";
import { SiemSource } from "../../../domain/alert/entities/Alert.entity";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

/**
 * SiemInboundWebhookController — presentation layer.
 * Handles POST /api/v1/webhooks/siem/:source
 * This is the actual door external SIEMs (Wazuh, Splunk, Defender, ELK) knock on.
 */
export class SiemInboundWebhookController {
  constructor(
    private readonly ingestAlert: IngestAlertFromSiemUseCase,
    private readonly siemAdapters: Partial<Record<SiemSource, ISiemAdapter>>
  ) {}

  handle = async (req: Request, res: Response): Promise<void> => {
    const source = req.params.source as SiemSource;
    const adapter = this.siemAdapters[source];

    if (!adapter) {
      res.status(400).json({
        error: `Unsupported SIEM source: ${source}`,
        supported: Object.keys(this.siemAdapters),
      });
      return;
    }

    // The HMAC signature was already verified by webhookAuth (see webhook.routes.ts).

    let normalized;
    try {
      normalized = adapter.normalize(req.body);
    } catch (err) {
      res.status(422).json({
        error: "Payload did not match expected shape for this SIEM",
        detail: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    // TODO: resolve tenantId from an API key / webhook token once multi-tenant auth exists.
    const tenantId = DEFAULT_TENANT_ID;

    const result = await this.ingestAlert.execute({ ...normalized, tenantId });

    // 202 Accepted: the alert is stored in the Alert Inbox for SOC triage (triageRequired: true). No incident is opened
    // and no AI runs until the SOC creates an incident. A repeat of an already-ingested alert (same source + external
    // id) is also 202, with duplicate: true (and the incident it already belongs to, if any).
    res.status(202).json({
      alertId: result.value.alert.id,
      status: result.value.alert.status,
      incidentId: result.value.incidentId,
      aiJob: result.value.aiJob,
      duplicate: result.value.duplicate,
      triageRequired: result.value.triageRequired,
    });
  };
}
