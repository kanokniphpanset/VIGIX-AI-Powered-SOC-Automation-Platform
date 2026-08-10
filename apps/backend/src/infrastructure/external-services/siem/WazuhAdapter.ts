import { AlertSeverity } from "../../../domain/alert/entities/Alert.entity";
import { ISiemAdapter, NormalizedAlertInput } from "./ISiemAdapter";

/**
 * Shape of the JSON Wazuh Manager sends (a subset of fields we actually use).
 * Full Wazuh alerts have many more fields — we only type what we read.
 */
interface WazuhAlertPayload {
  id?: string;
  timestamp?: string;
  rule?: {
    id?: string;
    level?: number;
    description?: string;
    mitre?: {
      id?: string[];
      tactic?: string[];
      technique?: string[];
    };
  };
  agent?: {
    id?: string;
    name?: string;
    ip?: string;
  };
  full_log?: string;
}

/**
 * WazuhAdapter.ts — infrastructure. Implements ISiemAdapter for Wazuh.
 * Maps Wazuh's rule.level (0-15 integer scale) onto our low/medium/high/critical scale.
 * Replacing this file (and registering a new one in container.ts) is all that's
 * needed to support a different Wazuh alert schema version — nothing else changes.
 */
export class WazuhAdapter implements ISiemAdapter {
  readonly source = "wazuh" as const;

  normalize(rawPayload: Record<string, unknown>): NormalizedAlertInput {
    const payload = rawPayload as WazuhAlertPayload;

    if (!payload.rule?.description) {
      throw new Error("Invalid Wazuh payload: missing rule.description");
    }

    return {
      externalAlertId: payload.id ?? `wazuh-${Date.now()}`,
      siemSource: "wazuh",
      severity: this.mapSeverity(payload.rule.level ?? 0),
      rawPayload: rawPayload,
      receivedAt: payload.timestamp ? new Date(payload.timestamp) : new Date(),
    };
  }

  /**
   * Wazuh rule levels run 0–15. This threshold mapping is a starting point —
   * tune it against your actual ruleset's level distribution.
   */
  private mapSeverity(level: number): AlertSeverity {
    if (level >= 14) return "critical";
    if (level >= 11) return "high";
    if (level >= 7) return "medium";
    return "low";
  }
}
