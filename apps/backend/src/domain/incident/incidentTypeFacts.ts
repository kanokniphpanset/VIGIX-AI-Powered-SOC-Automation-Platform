/**
 * incidentTypeFacts — the alert fields that matter for an incident type, read from the stored Wazuh payload as
 * received (pure, no I/O, no inference). An SSH brute force shows the user, source port and attempt count; a
 * PowerShell case shows the command line and parent process; and so on. Absent fields are left out, never guessed.
 * Keys are stable ids the UI translates.
 */
export type AlertFactKey =
  | "user"
  | "sourcePort"
  | "attempts"
  | "program"
  | "logonType"
  | "workstation"
  | "filePath"
  | "sha256"
  | "process"
  | "parentProcess"
  | "commandLine"
  | "scriptBlock"
  | "url"
  | "httpStatus"
  | "log";

export interface AlertFact {
  key: AlertFactKey;
  value: string;
}

const MAX_VALUE = 500;

function at(payload: unknown, path: string): string | null {
  let v: unknown = payload;
  for (const part of path.split(".")) {
    if (!v || typeof v !== "object" || Array.isArray(v)) return null;
    v = (v as Record<string, unknown>)[part];
  }
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v !== "string" || !v.trim()) return null;
  const s = v.trim();
  return s.length > MAX_VALUE ? `${s.slice(0, MAX_VALUE)}…` : s;
}
const first = (payload: unknown, ...paths: string[]) => paths.map((p) => at(payload, p)).find((v) => v !== null) ?? null;

/** Windows Sysmon "Hashes" field ("SHA256=ab…,MD5=…") -> the SHA256 value. */
function sha256FromHashes(hashes: string | null): string | null {
  const m = hashes?.match(/SHA256=([0-9a-fA-F]{64})/);
  return m ? m[1] : null;
}

const WIN = "data.win.eventdata";
const readers: Record<AlertFactKey, (p: unknown) => string | null> = {
  user: (p) => first(p, "data.dstuser", "data.srcuser", `${WIN}.targetUserName`, `${WIN}.user`),
  sourcePort: (p) => first(p, "data.srcport"),
  attempts: (p) => first(p, "rule.firedtimes"),
  program: (p) => first(p, "predecoder.program_name", "decoder.name"),
  logonType: (p) => first(p, `${WIN}.logonType`),
  workstation: (p) => first(p, `${WIN}.workstationName`),
  filePath: (p) => first(p, "syscheck.path", `${WIN}.targetFilename`),
  sha256: (p) => first(p, "syscheck.sha256_after") ?? sha256FromHashes(first(p, `${WIN}.hashes`)),
  process: (p) => first(p, `${WIN}.image`, "data.process.name"),
  parentProcess: (p) => first(p, `${WIN}.parentImage`),
  commandLine: (p) => first(p, `${WIN}.commandLine`),
  scriptBlock: (p) => first(p, `${WIN}.scriptBlockText`),
  url: (p) => first(p, "data.url"),
  httpStatus: (p) => first(p, "data.id"),
  log: (p) => first(p, "full_log"),
};

/** Which fields each playbook incident type needs (knowledge/playbooks). Unknown type -> a general set. */
const FACTS_BY_TYPE: Record<string, AlertFactKey[]> = {
  SSH_BRUTE_FORCE: ["user", "sourcePort", "attempts", "program", "log"],
  ACCOUNT_COMPROMISE: ["user", "logonType", "workstation", "attempts", "log"],
  MALWARE: ["filePath", "sha256", "process", "parentProcess", "user", "log"],
  SQL_INJECTION: ["url", "httpStatus", "attempts", "log"],
  POWERSHELL: ["commandLine", "scriptBlock", "parentProcess", "process", "user", "log"],
};
const GENERAL: AlertFactKey[] = ["user", "process", "commandLine", "filePath", "url", "attempts", "log"];

export function incidentTypeFacts(incidentType: string | null, rawPayload: unknown): AlertFact[] {
  const keys = (incidentType && FACTS_BY_TYPE[incidentType]) || GENERAL;
  return keys.map((key) => ({ key, value: readers[key](rawPayload) })).filter((f): f is AlertFact => f.value !== null);
}
