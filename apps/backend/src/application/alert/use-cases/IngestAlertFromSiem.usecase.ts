import { randomUUID } from "node:crypto";
import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { Alert } from "../../../domain/alert/entities/Alert.entity";
import { NormalizedAlertInput } from "../../../infrastructure/external-services/siem/ISiemAdapter";
import { IAiOrchestratorPort } from "../../agent-orchestration/ports/IAiOrchestratorPort";
import { Result } from "../../../shared/result/Result";

export interface IngestAlertFromSiemInput extends NormalizedAlertInput {
  tenantId: string;
}

export interface IngestAlertFromSiemOutput {
  alert: Alert;
  pipelineDispatched: boolean;
}

/**
 * IngestAlertFromSiemUseCase — application layer.
 * SIEM-agnostic: it only ever sees NormalizedAlertInput, never a raw Wazuh/Splunk shape.
 * That normalization already happened in the adapter, one layer down.
 * After saving, it dispatches the AI pipeline via IAiOrchestratorPort — a port, so the
 * use-case has no idea LangGraph exists.
 */
export class IngestAlertFromSiemUseCase {
  constructor(
    private readonly alertRepository: IAlertRepository,
    private readonly aiOrchestrator: IAiOrchestratorPort
  ) {}

  async execute(input: IngestAlertFromSiemInput): Promise<Result<IngestAlertFromSiemOutput>> {
    const alert = Alert.create({
      id: randomUUID(),
      tenantId: input.tenantId,
      externalAlertId: input.externalAlertId,
      siemSource: input.siemSource,
      rawPayload: input.rawPayload,
      severity: input.severity,
      status: "received",
      receivedAt: input.receivedAt,
      createdAt: new Date(),
    });

    const saved = await this.alertRepository.save(alert);

    // Fire the AI pipeline. If the orchestrator is unreachable, the alert is
    // still saved — it just stays in "received" status for manual/retry pickup.
    let pipelineDispatched = false;
    try {
      await this.aiOrchestrator.dispatch({ alertId: saved.id, tenantId: saved.tenantId });
      pipelineDispatched = true;
    } catch (err) {
      console.error("Failed to dispatch AI pipeline for alert", saved.id, err);
    }

    return Result.ok({ alert: saved, pipelineDispatched });
  }
}

