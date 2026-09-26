import { Severity } from "../../domain/policy/entities/PolicyEvaluationTypes";
import { toSeverity } from "../../domain/incident/severity";
import { Result } from "../../shared/result/Result";

/** Stored facts behind an incident's severity (no AI value exists or is read). */
export interface IncidentSeverityFacts {
  /** incidents.priority — the SOC-validated incident severity. */
  incidentSeverity: string;
  /** The primary Wazuh alert: its mapped severity and the raw rule level it was derived from. */
  alertSeverity: string | null;
  ruleLevel: number | null;
  ruleId: string | null;
  /** Latest SEVERITY_VALIDATED audit (the SOC decision), if any. */
  latestValidation: { severity: string | null; reason: string | null; actor: string; at: Date } | null;
}

export interface IIncidentSeverityReader {
  read(tenantId: string, incidentId: string): Promise<IncidentSeverityFacts | null>;
}

export interface IncidentSeverityView {
  /** Where the severity comes from — always the Wazuh rule level mapping; never AI. */
  source: "WAZUH_RULE_LEVEL";
  /** Deterministic mapping of the primary alert's Wazuh rule level (immutable). */
  wazuhSeverity: Severity | null;
  wazuhRuleLevel: number | null;
  wazuhRuleId: string | null;
  /** The incident severity the SOC works with (starts as wazuhSeverity; the SOC confirms or overrides it). */
  severity: Severity;
  /** True when the SOC set a value different from the Wazuh severity. */
  overridden: boolean;
  /** The SOC's mandatory reason for the override (null when not overridden). */
  override: { reason: string | null; actor: string; at: string } | null;
}

/** Read model for the incident page: Wazuh severity, SOC-validated severity and override reason, kept separate. */
export class GetIncidentSeverityUseCase {
  constructor(private readonly reader: IIncidentSeverityReader) {}

  async execute(input: { tenantId: string; incidentId: string }): Promise<Result<IncidentSeverityView, "INCIDENT_NOT_FOUND">> {
    const facts = await this.reader.read(input.tenantId, input.incidentId);
    if (!facts) return Result.fail("INCIDENT_NOT_FOUND");
    const wazuhSeverity = toSeverity(facts.alertSeverity);
    const severity = toSeverity(facts.incidentSeverity) ?? wazuhSeverity ?? "MEDIUM";
    const overridden = !!wazuhSeverity && wazuhSeverity !== severity;
    const v = facts.latestValidation;
    return Result.ok({
      source: "WAZUH_RULE_LEVEL",
      wazuhSeverity,
      wazuhRuleLevel: facts.ruleLevel,
      wazuhRuleId: facts.ruleId,
      severity,
      overridden,
      override: overridden && v && toSeverity(v.severity) === severity ? { reason: v.reason, actor: v.actor, at: v.at.toISOString() } : null,
    });
  }
}
