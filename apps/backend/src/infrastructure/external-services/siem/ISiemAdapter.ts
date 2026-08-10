import { AlertSeverity, SiemSource } from "../../../domain/alert/entities/Alert.entity";

/**
 * Normalized shape every SIEM adapter must produce, regardless of how
 * wildly different the source's native JSON looks.
 */
export interface NormalizedAlertInput {
  externalAlertId: string;
  siemSource: SiemSource;
  severity: AlertSeverity;
  rawPayload: Record<string, unknown>;
  receivedAt: Date;
}

/**
 * ISiemAdapter — port. Each SIEM (Wazuh, Splunk, Defender, ELK) gets its own
 * implementation that knows that vendor's alert JSON shape and severity scale.
 * The rest of the system only ever talks to NormalizedAlertInput.
 */
export interface ISiemAdapter {
  readonly source: SiemSource;
  normalize(rawPayload: Record<string, unknown>): NormalizedAlertInput;
}
