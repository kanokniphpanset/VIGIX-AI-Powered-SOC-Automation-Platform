import { PolicyEvaluator } from "./PolicyEvaluator";
import { IIncidentIntakePolicy } from "../../application/alert/use-cases/IngestAlertFromSiem.usecase";
import { Severity } from "../../domain/policy/entities/PolicyEvaluationTypes";

/** Policy INTAKE decision for an ingested alert, from the one PolicyEvaluator (no separate intake rules engine). */
export class PolicyIncidentIntake implements IIncidentIntakePolicy {
  constructor(private readonly policyEvaluator: PolicyEvaluator) {}

  async evaluate(input: { tenantId: string; severity: string }): Promise<{ autoCreateIncident: boolean; matchedPolicies: string[] }> {
    const result = await this.policyEvaluator.evaluate(input.tenantId, { severity: input.severity.toUpperCase() as Severity });
    return { autoCreateIncident: result.autoCreateIncident, matchedPolicies: result.matchedPolicies };
  }
}
