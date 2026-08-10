import { AlertSeverity } from "../../../domain/alert/entities/Alert.entity";
import { ISiemAdapter, NormalizedAlertInput } from "./ISiemAdapter";

/**
 * Shape of a Splunk Enterprise Security notable event (subset of fields used).
 * Splunk typically posts this via a webhook alert action or HEC forwarder.
 */
interface SplunkAlertPayload {
  event_id?: string;
  _time?: string;
  urgency?: string; // informational | low | medium | high | critical
  search_name?: string;
  result?: Record<string, unknown>;
}

export class SplunkAdapter implements ISiemAdapter {
  readonly source = "splunk" as const;

  normalize(rawPayload: Record<string, unknown>): NormalizedAlertInput {
    const payload = rawPayload as SplunkAlertPayload;

    if (!payload.search_name) {
      throw new Error("Invalid Splunk payload: missing search_name");
    }

    return {
      externalAlertId: payload.event_id ?? `splunk-${Date.now()}`,
      siemSource: "splunk",
      severity: this.mapSeverity(payload.urgency ?? "low"),
      rawPayload,
      receivedAt: payload._time ? new Date(Number(payload._time) * 1000) : new Date(),
    };
  }

  private mapSeverity(urgency: string): AlertSeverity {
    const normalized = urgency.toLowerCase();
    if (normalized === "critical") return "critical";
    if (normalized === "high") return "high";
    if (normalized === "medium") return "medium";
    return "low";
  }
}
