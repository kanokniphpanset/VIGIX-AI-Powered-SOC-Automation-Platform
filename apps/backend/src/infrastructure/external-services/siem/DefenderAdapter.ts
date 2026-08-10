import { AlertSeverity } from "../../../domain/alert/entities/Alert.entity";
import { ISiemAdapter, NormalizedAlertInput } from "./ISiemAdapter";

/**
 * Shape of a Microsoft Defender for Endpoint / Microsoft 365 Defender alert,
 * as delivered via a Graph Security API webhook subscription or Sentinel forward.
 */
interface DefenderAlertPayload {
  id?: string;
  createdDateTime?: string;
  severity?: string; // informational | low | medium | high
  title?: string;
  category?: string;
  evidence?: unknown[];
}

export class DefenderAdapter implements ISiemAdapter {
  readonly source = "defender" as const;

  normalize(rawPayload: Record<string, unknown>): NormalizedAlertInput {
    const payload = rawPayload as DefenderAlertPayload;

    if (!payload.title) {
      throw new Error("Invalid Defender payload: missing title");
    }

    return {
      externalAlertId: payload.id ?? `defender-${Date.now()}`,
      siemSource: "defender",
      severity: this.mapSeverity(payload.severity ?? "low"),
      rawPayload,
      receivedAt: payload.createdDateTime ? new Date(payload.createdDateTime) : new Date(),
    };
  }

  private mapSeverity(severity: string): AlertSeverity {
    const normalized = severity.toLowerCase();
    if (normalized === "high") return "critical"; // Defender's ceiling is "high"; treat as our critical
    if (normalized === "medium") return "high";
    if (normalized === "low") return "medium";
    return "low"; // informational
  }
}
