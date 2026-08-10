import { AlertSeverity } from "../../../domain/alert/entities/Alert.entity";
import { ISiemAdapter, NormalizedAlertInput } from "./ISiemAdapter";

/**
 * Shape of an Elastic Security detection alert (subset of fields used),
 * as delivered via Kibana's webhook connector on a detection rule.
 */
interface ElkAlertPayload {
  "kibana.alert.uuid"?: string;
  "@timestamp"?: string;
  "kibana.alert.severity"?: string; // low | medium | high | critical
  "kibana.alert.rule.name"?: string;
  "kibana.alert.risk_score"?: number;
}

export class ElkAdapter implements ISiemAdapter {
  readonly source = "elk" as const;

  normalize(rawPayload: Record<string, unknown>): NormalizedAlertInput {
    const payload = rawPayload as ElkAlertPayload;

    if (!payload["kibana.alert.rule.name"]) {
      throw new Error("Invalid ELK payload: missing kibana.alert.rule.name");
    }

    return {
      externalAlertId: payload["kibana.alert.uuid"] ?? `elk-${Date.now()}`,
      siemSource: "elk",
      severity: this.mapSeverity(
        payload["kibana.alert.severity"],
        payload["kibana.alert.risk_score"]
      ),
      rawPayload,
      receivedAt: payload["@timestamp"] ? new Date(payload["@timestamp"]) : new Date(),
    };
  }

  private mapSeverity(severity?: string, riskScore?: number): AlertSeverity {
    if (severity) {
      const normalized = severity.toLowerCase();
      if (["low", "medium", "high", "critical"].includes(normalized)) {
        return normalized as AlertSeverity;
      }
    }
    // Fall back to Elastic's 0-100 risk_score if severity field is absent
    if (typeof riskScore === "number") {
      if (riskScore >= 75) return "critical";
      if (riskScore >= 50) return "high";
      if (riskScore >= 25) return "medium";
    }
    return "low";
  }
}
