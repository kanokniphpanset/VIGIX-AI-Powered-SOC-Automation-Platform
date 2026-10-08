import { IocType } from "../Investigation.types";

/**
 * Evidence Contract v2 (docs/architecture/evidence-contract-v2.md). One document per Wazuh alert, built only from
 * fields the alert actually carries: a missing scalar is null, a missing list is [], nothing is invented. Detection
 * metadata (rule, MITRE) is kept apart from attack evidence (observed telemetry).
 */
export const EVIDENCE_CONTRACT_VERSION = 2 as const;

/** UNKNOWN_ORIGIN: no mock/harness marker, but the id is not a native Wazuh id either - never claimed as real. */
export type ProvenanceClass = "REAL_TELEMETRY" | "HARNESS_GENERATED" | "MOCK_FIXTURE" | "UNKNOWN_ORIGIN";
export type EvidenceCategory = "network" | "process" | "file" | "syscheck" | "authentication" | "email" | "powershell" | "http" | "account";
/** NOT_AVAILABLE is reserved for coverage-level facts (archives off, no Sysmon EID 3); the per-alert extractor emits OBSERVED / INCOMPLETE. */
export type CompletenessState = "OBSERVED" | "INCOMPLETE" | "NOT_AVAILABLE";

export type IocRole = "SOURCE" | "DESTINATION" | "ENDPOINT_SELF" | "ACTOR" | "TARGET" | "ARTIFACT" | "UNKNOWN";

export interface MitreTechniqueV2 {
  id: string;
  name: string | null;
}

export interface DetectionV2 {
  rule: { id: string; level: number; description: string; groups: string[]; firedTimes: number | null; frequency: number | null };
  /** Detection metadata only - never proof the technique succeeded. tactics is an unpaired set. */
  mitre: { techniques: MitreTechniqueV2[]; tactics: string[] };
}

export interface NetworkEvidence {
  src: { ip: string | null; port: number | null };
  dst: { ip: string | null; port: number | null };
  dnsQuery: string | null;
  dnsStatus: string | null;
  url: string | null;
  bytesOut: number | null;
  durationSeconds: number | null;
  /** Derived (src == agent.ip), else null. */
  direction: { value: "OUTBOUND"; derivedFrom: string } | null;
}

export interface ProcessRef {
  image: string | null;
  commandLine: string | null;
  pid: string | null;
  guid: string | null;
  user: { domain: string | null; name: string | null; raw: string } | null;
}

export interface ProcessEvidence extends ProcessRef {
  startedAt: string | null;
  integrityLevel: string | null;
  hashes: { alg: string; value: string }[];
  parent: ProcessRef & { name: string | null };
  windowsEvent: { id: string | null; channel: string | null; provider: string | null };
}

export interface FileEvidence {
  path: string | null;
  hashes: { md5: string | null; sha1: string | null; sha256: string | null };
}

export interface SyscheckValueSet<T> {
  after: T;
  before: T;
}

export interface SyscheckEvidence {
  path: string | null;
  operation: string | null;
  detectionMode: string | null;
  hashes: {
    after: { md5: string | null; sha1: string | null; sha256: string | null; lastKnown: boolean };
    before: { md5: string | null; sha1: string | null; sha256: string | null };
  };
  size: SyscheckValueSet<number | null>;
  permissions: SyscheckValueSet<string | null>;
  owner: SyscheckValueSet<{ uid: string | null; gid: string | null; uname: string | null; gname: string | null }>;
  modifiedAt: SyscheckValueSet<string | null>;
  inode: SyscheckValueSet<string | null>;
  changedAttributes: string[];
  /** Wazuh's content diff is never copied (it can hold file contents / secrets); only its presence is recorded. */
  diffPresent: boolean;
}

export interface AuthenticationEvidence {
  result: { value: "SUCCESS" | "FAILURE"; derivedFrom: string } | null;
  remote: { ip: string | null; port: number | null };
  account: string | null;
  attemptedAccount: string | null;
  accountDomain: string | null;
  accountSid: string | null;
  actor: { name: string | null; domain: string | null; sid: string | null; isMachineAccount: boolean | null };
  logon: { type: string | null; id: string | null; process: string | null; package: string | null };
}

export interface EmailEvidence {
  sender: string | null;
  recipients: string[];
  subject: string | null;
}

export interface PowerShellEvidence {
  scriptBlockText: string | null;
  scriptBlockId: string | null;
  part: number | null;
  totalParts: number | null;
}

export interface HttpEvidence {
  requestTarget: string | null;
  method: string | null;
  status: number | null;
}

export interface AccountChangeEvidence {
  user: string | null;
  group: string | null;
  uid: string | null;
  gid: string | null;
  home: string | null;
  shell: string | null;
}

export interface IocV2 {
  type: IocType;
  value: string;
  role: IocRole;
  /** The Wazuh JSON path the value was read from. */
  sourcePath: string;
  /** Why the role was assigned (null when UNKNOWN). */
  roleBasis: string | null;
  /** True for a hash/path taken from a deleted file: history, not a live indicator. */
  lastKnown: boolean;
}

export interface ProvenanceV2 {
  class: ProvenanceClass;
  classBasis: string[];
  source: {
    siem: "wazuh";
    alertId: string;
    alertRowId: string | null;
    indexerRef: { index: string; docId: string } | null;
    /** Derived dedup key for the underlying EVENT (one log line can raise several alerts): EventChannel record id, or a hash of agent+log time+log line. null when neither is available - never guessed. */
    eventKey: string | null;
    manager: string | null;
    decoder: { name: string | null; parent: string | null };
    location: string | null;
    inputType: string | null;
  };
  agent: { id: string | null; name: string | null; ip: string | null };
  time: {
    detectedAt: string;
    reportedAt: string | null;
    reportedAtRaw: string | null;
    eventAt: string | null;
    receivedAt: string;
  };
  completeness: Partial<Record<EvidenceCategory, CompletenessState>>;
  /** Expected Wazuh paths that were absent, e.g. ["data.win.eventdata.ipAddress"]. */
  missing: string[];
}

export interface EvidenceV2 {
  contractVersion: typeof EVIDENCE_CONTRACT_VERSION;
  provenance: ProvenanceV2;
  detection: DetectionV2;
  evidence: {
    network: NetworkEvidence;
    process: ProcessEvidence;
    file: FileEvidence;
    syscheck: SyscheckEvidence;
    authentication: AuthenticationEvidence;
    email: EmailEvidence;
    powershell: PowerShellEvidence;
    http: HttpEvidence;
    account: AccountChangeEvidence;
  };
  iocs: IocV2[];
  fullLog: string | null;
}

export interface EvidenceV2Context {
  /** VIGIX alerts.id, when the alert is stored. */
  alertRowId?: string | null;
  /** VIGIX's true receipt time (alerts.createdAt) - NOT alerts.receivedAt, which is the Wazuh alert time. */
  receivedAt: Date;
  /** alerts.externalAlertId, used for the mock-id marker. Defaults to the payload's own `id`. */
  externalAlertId?: string | null;
  /** Set only when the alert was read back from the Indexer. */
  indexerRef?: { index: string; docId: string } | null;
  /** Alert ids of known mock fixtures (e.g. from the mock-alert catalog), so legacy fixtures sent with their own id are not read as real. */
  knownFixtureIds?: ReadonlySet<string>;
}
