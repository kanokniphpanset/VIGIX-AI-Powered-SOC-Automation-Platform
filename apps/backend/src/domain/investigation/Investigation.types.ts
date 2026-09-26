/**
 * Investigation module domain types. An Investigation is ONE cycle of an Incident's investigation
 * (Incident.investigationNumber is the current cycle). Evidence and IOCs belong to a cycle, so a
 * later cycle never silently inherits an earlier cycle's findings.
 */

export const INVESTIGATION_STATUSES = ["ACTIVE", "COMPLETED"] as const;
export type InvestigationStatus = (typeof INVESTIGATION_STATUSES)[number];

export const EVIDENCE_TYPES = [
  "WAZUH_ALERT",
  "WAZUH_EVENT",
  "WINDOWS_EVENT",
  "LINUX_LOG",
  "PROCESS_EVENT",
  "NETWORK_CONNECTION",
  "AUTHENTICATION_EVENT",
  "FILE_EVENT",
  "REGISTRY_EVENT",
  "EMAIL",
  "THREAT_INTELLIGENCE",
  "ANALYST_NOTE",
  "SCREENSHOT_ARTIFACT",
  "QUERY_RESULT",
  "OTHER",
] as const;
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

/** Types only the backend may create - derived from a stored alert or a SIEM query, never typed in. */
export const SYSTEM_ONLY_EVIDENCE_TYPES: readonly EvidenceType[] = ["WAZUH_ALERT", "WAZUH_EVENT"];

export const EVIDENCE_RELEVANCE = ["HIGH", "MEDIUM", "LOW"] as const;
export type EvidenceRelevance = (typeof EVIDENCE_RELEVANCE)[number];

/** SYSTEM = derived by the backend; MANUAL = entered by an analyst. Stamped server-side, never taken from a request. */
export type EvidenceOrigin = "SYSTEM" | "MANUAL";

/** Where a manually entered piece of evidence came from. WAZUH means "taken from Wazuh by the analyst", still origin MANUAL. */
export const MANUAL_EVIDENCE_SOURCES = ["WAZUH", "SPLUNK", "DEFENDER", "ELK", "EDR", "FIREWALL", "EMAIL_GATEWAY", "ANALYST", "OTHER"] as const;

export const IOC_TYPES = [
  "IPV4",
  "IPV6",
  "DOMAIN",
  "URL",
  "MD5",
  "SHA1",
  "SHA256",
  "FILE_NAME",
  "FILE_PATH",
  "REGISTRY_KEY",
  "REGISTRY_VALUE",
  "EMAIL",
  "USERNAME",
  "PROCESS_NAME",
  "PROCESS_ID",
  "HOSTNAME",
  "MAC",
  "CVE",
  "CERT_FINGERPRINT",
  "COMMAND_LINE",
  "HTTP_REQUEST",
  "OTHER",
] as const;
export type IocType = (typeof IOC_TYPES)[number];

export const IOC_STATUSES = ["ACTIVE", "BENIGN", "FALSE_POSITIVE"] as const;
export type IocStatus = (typeof IOC_STATUSES)[number];

export interface InvestigationRecord {
  id: string;
  incidentId: string;
  investigationNumber: number;
  status: InvestigationStatus;
  startedAt: Date;
  completedAt: Date | null;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
  evidenceCount: number;
  iocCount: number;
  /** True for the incident's current cycle (Incident.investigationNumber). */
  isCurrent: boolean;
}

export interface EvidenceRecord {
  id: string;
  investigationId: string;
  alertId: string | null;
  type: string;
  source: string;
  origin: EvidenceOrigin;
  timestamp: Date;
  title: string;
  description: string | null;
  rawData: unknown;
  structuredData: unknown;
  confidence: number | null;
  relevance: string | null;
  createdBy: string;
  createdAt: Date;
  iocIds: string[];
}

export interface IocRecord {
  id: string;
  incidentId: string;
  investigationId: string | null;
  iocType: string;
  iocValue: string;
  source: string;
  reputationScore: number | null;
  confidence: number | null;
  status: string;
  firstSeen: Date | null;
  lastSeen: Date | null;
  createdBy: string | null;
  createdAt: Date;
  /** Related-alert evidence: the other Wazuh alert the SOC observed this indicator in (null = this incident's own). */
  sourceAlertId: string | null;
  /** Why the SOC linked the indicator to this incident (set together with sourceAlertId). */
  addedReason: string | null;
  evidenceIds: string[];
}

export interface EvidenceAlertSummary {
  id: string;
  externalAlertId: string;
  siemSource: string;
  severity: string;
  receivedAt: Date;
  rawPayload: unknown;
}

export interface EvidenceDetail extends EvidenceRecord {
  iocs: IocRecord[];
  alert: EvidenceAlertSummary | null;
}

export interface CreateEvidenceData {
  investigationId: string;
  alertId: string | null;
  type: EvidenceType;
  source: string;
  origin: EvidenceOrigin;
  timestamp: Date;
  title: string;
  description: string | null;
  rawData: unknown;
  structuredData: unknown;
  confidence: number | null;
  relevance: EvidenceRelevance | null;
  createdBy: string;
  iocIds: string[];
}

export interface CreateIocData {
  incidentId: string;
  investigationId: string;
  iocType: IocType;
  iocValue: string;
  source: string;
  reputationScore: number | null;
  confidence: number | null;
  status: IocStatus;
  firstSeen: Date | null;
  lastSeen: Date | null;
  createdBy: string;
  sourceAlertId?: string | null;
  addedReason?: string | null;
}

/** Thrown by createIoc when (investigation, type, value) already exists. */
export class DuplicateIocError extends Error {
  constructor(public readonly existingIocId: string | null) {
    super("DUPLICATE_IOC");
  }
}
