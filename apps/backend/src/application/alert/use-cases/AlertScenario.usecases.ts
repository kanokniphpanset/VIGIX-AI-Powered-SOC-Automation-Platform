import { Result } from "../../../shared/result/Result";
import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { IAlertScenarioRepository } from "../../../domain/alert/repositories/IAlertScenarioRepository";
import { AttackScenario, findAttackScenario } from "../../../domain/alert/attackScenarios";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";

export type SetAlertScenarioError = "ALERT_NOT_FOUND" | "UNKNOWN_SCENARIO";

/**
 * Labels a real, already-ingested alert with a lab test scenario (or removes the label with scenarioId = null).
 * The alert itself and its raw SIEM payload are never changed; every change is audited with the previous value.
 */
export class SetAlertScenarioUseCase {
  constructor(
    private readonly alerts: IAlertRepository,
    private readonly scenarios: IAlertScenarioRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { tenantId: string; alertId: string; scenarioId: string | null; actor: string }): Promise<Result<{ alertId: string; scenario: AttackScenario | null }, SetAlertScenarioError>> {
    const alert = await this.alerts.findById(input.alertId, input.tenantId);
    if (!alert) return Result.fail("ALERT_NOT_FOUND");
    const scenario = input.scenarioId ? findAttackScenario(input.scenarioId) : null;
    if (input.scenarioId && !scenario) return Result.fail("UNKNOWN_SCENARIO");

    const previous = (await this.scenarios.findByAlertIds([input.alertId], input.tenantId)).get(input.alertId)?.scenarioId ?? null;
    if (scenario) await this.scenarios.set(input.alertId, input.tenantId, scenario.id, input.actor);
    else await this.scenarios.clear(input.alertId, input.tenantId);

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: scenario ? "ALERT_SCENARIO_TAGGED" : "ALERT_SCENARIO_CLEARED",
      entity: "Alert",
      entityId: input.alertId,
      metadata: { externalAlertId: alert.externalAlertId, previousScenarioId: previous, scenarioId: scenario?.id ?? null },
    });
    return Result.ok({ alertId: input.alertId, scenario });
  }
}
