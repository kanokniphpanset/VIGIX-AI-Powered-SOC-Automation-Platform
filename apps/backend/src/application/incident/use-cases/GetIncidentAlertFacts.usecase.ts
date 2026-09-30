import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { summarizeAlert } from "../../../domain/alert/alertSummary";
import { AlertFact, incidentTypeFacts } from "../../../domain/incident/incidentTypeFacts";
import { PlaybookSelector } from "../../recommendation/services/PlaybookSelector";
import { Result } from "../../../shared/result/Result";
import { ListAlertsByIncidentUseCase } from "./ListAlertsByIncident.usecase";
import { ListMitreMappingsByIncidentUseCase } from "./ListMitreMappingsByIncident.usecase";
import type { IncidentResponseSetupService } from "../services/IncidentResponseSetupService";

export interface IncidentAlertFactRow {
  /** VIGIX alert id. */
  alertId: string;
  externalAlertId: string;
  /** Wazuh rule-level severity and the level itself. */
  severity: string;
  ruleLevel: number | null;
  ruleDescription: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  mitreTechniques: string[];
  /** From this alert's own Wazuh techniques; the incident's type when they match no playbook. */
  incidentType: string | null;
  /** Type-specific fields from the Wazuh payload (e.g. command line for POWERSHELL). */
  facts: AlertFact[];
}

export interface IncidentAlertFacts {
  /** The incident type, from the playbook its techniques match (same rule as the Recommendation); null = none yet. */
  incidentType: string | null;
  playbook: { code: string; name: string } | null;
  matchedTechniques: string[];
  rows: IncidentAlertFactRow[];
}

/**
 * Investigation table: each alert of the incident with the facts that matter for the incident type. Read-only.
 * The type is chosen deterministically by PlaybookSelector from the incident's MITRE mappings plus the alerts' own
 * Wazuh techniques — never by AI, never guessed (no match -> null).
 */
export class GetIncidentAlertFactsUseCase {
  private readonly selector = new PlaybookSelector();

  constructor(
    private readonly alerts: ListAlertsByIncidentUseCase,
    private readonly mitre: ListMitreMappingsByIncidentUseCase,
    private readonly playbooks: IPlaybookRepository,
    /** When the SOC confirmed a type, it is the incident's type and every row's. */
    private readonly setup?: Pick<IncidentResponseSetupService, "resolve">
  ) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Result<IncidentAlertFacts, "INCIDENT_NOT_FOUND">> {
    const [alerts, mappings] = await Promise.all([this.alerts.execute(input), this.mitre.execute(input)]);
    if (alerts.isFailure || mappings.isFailure) return Result.fail("INCIDENT_NOT_FOUND");
    const playbooks = await this.playbooks.findAll(input.tenantId);

    const summaries = alerts.value.map((a) => ({ alert: a, summary: summarizeAlert(a.rawPayload) }));
    const techniques = [...new Set([...mappings.value.map((m) => m.techniqueId), ...summaries.flatMap((s) => s.summary.mitreTechniques)])];
    const resolved = this.setup ? await this.setup.resolve(input.incidentId, input.tenantId) : null;
    const socConfirmed = resolved?.isSuccess && resolved.value.typeSource === "SOC";
    const incident = resolved?.isSuccess ? resolved.value.selected : this.selector.select(playbooks, techniques);
    const incidentType = incident?.incidentType ?? null;

    return Result.ok({
      incidentType,
      playbook: incident ? { code: incident.code, name: incident.name } : null,
      matchedTechniques: incident?.matchedTechniques ?? [],
      rows: summaries.map(({ alert, summary }) => {
        const type = socConfirmed ? incidentType : (this.selector.select(playbooks, summary.mitreTechniques)?.incidentType ?? incidentType);
        return {
          alertId: alert.id,
          externalAlertId: alert.externalAlertId,
          severity: alert.severity,
          ruleLevel: summary.ruleLevel,
          ruleDescription: summary.ruleDescription,
          sourceIp: summary.sourceIp,
          destinationIp: summary.destinationIp,
          mitreTechniques: summary.mitreTechniques,
          incidentType: type,
          facts: incidentTypeFacts(type, alert.rawPayload),
        };
      }),
    });
  }
}
