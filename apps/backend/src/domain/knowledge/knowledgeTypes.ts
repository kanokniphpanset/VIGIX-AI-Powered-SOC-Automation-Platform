/**
 * Shared vocabulary of the VIGIX response knowledge (attack types, target kinds, evidence requirements,
 * verification methods). Pure data — no I/O. The Action Catalog, Playbooks, Runbooks and Policies in Postgres are
 * seeded from / checked against this vocabulary (prisma/seeds/*, test/KnowledgeCatalog.test.ts), and the
 * RecommendationValidator enforces it deterministically. The AI never extends it.
 */

/** The attack types VIGIX has response knowledge for (the 10 evaluation attack cases). */
export const ATTACK_TYPES = [
  "BRUTE_FORCE",
  "MALWARE",
  "PHISHING",
  "ACCOUNT_COMPROMISE",
  "POWERSHELL",
  "SQL_INJECTION",
  "COMMAND_AND_CONTROL",
  "SUSPICIOUS_PROCESS_EXECUTION",
  "DATA_EXFILTRATION",
  "PRIVILEGE_ESCALATION",
] as const;
export type AttackType = (typeof ATTACK_TYPES)[number];

/** What kind of recorded value a containment Action operates on. */
export type TargetKind = "ip" | "domain" | "url" | "account" | "host" | "email" | "hash" | "file" | "process" | "command" | "other";

/** Kind of a recorded IOC, from its iocType (Wazuh / pipeline / analyst vocabulary). */
export function iocKind(iocType: string): TargetKind {
  const t = iocType.toLowerCase();
  if (["ipv4", "ipv6", "ip", "srcip", "src_ip", "dstip", "dst_ip"].includes(t)) return "ip";
  if (["domain", "fqdn"].includes(t)) return "domain";
  if (t === "url") return "url";
  if (["username", "user", "account"].includes(t)) return "account";
  if (t === "email") return "email";
  if (["hostname", "host"].includes(t)) return "host";
  if (["md5", "sha1", "sha256", "hash"].includes(t)) return "hash";
  if (["file", "filepath", "file_path", "path"].includes(t)) return "file";
  if (["process", "process_name", "image"].includes(t)) return "process";
  if (["command", "cmdline", "command_line"].includes(t)) return "command";
  return "other";
}

/**
 * Evidence requirements that can be checked DETERMINISTICALLY against the backend-built recommendation context
 * (application/recommendation/services/ActionEvidence.ts). They check that the evidence is RECORDED — whether it is
 * malicious stays the SOC/IR judgement. Anything that cannot be checked from recorded data (a PID, "evidence of
 * credential compromise") is an analyst-confirmed precondition of the Action's runbook instead.
 */
export const EVIDENCE_REQUIREMENTS = {
  VALIDATED_IOC_TARGET: "The target is an evidence-linked or analyst-added IOC (or an affected host) of the kind the Action operates on.",
  RELATED_EVENT: "An evidence row of this investigation cycle names the target (or an analyst added the IOC to the investigation).",
  SUPPORTING_EVIDENCE: "This investigation cycle has at least one evidence row.",
  AFFECTED_ENDPOINT: "At least one affected endpoint is recorded in this cycle's evidence.",
  SUSPICIOUS_ACTIVITY_EVIDENCE: "An evidence row records the activity on the affected endpoint (the target endpoint for host actions).",
  FILE_HASH: "A file hash IOC is recorded and linked to the evidence.",
  FILE_PATH: "A file path IOC is recorded and linked to the evidence.",
  PROCESS_IDENTIFIER: "A process IOC is recorded and linked to the evidence.",
  COMMAND_LINE: "A command-line IOC is recorded and linked to the evidence.",
  ACCOUNT_IDENTIFIER: "An account IOC is recorded and linked to the evidence.",
  AUTHENTICATION_EVIDENCE: "An evidence row (authentication / activity event) names the account.",
  EMAIL_MESSAGE: "An e-mail IOC (message / sender) is recorded and linked to the evidence.",
} as const;
export type EvidenceRequirementId = keyof typeof EVIDENCE_REQUIREMENTS;
export const EVIDENCE_REQUIREMENT_IDS = Object.keys(EVIDENCE_REQUIREMENTS) as EvidenceRequirementId[];

/** How IR / the platform verifies an executed containment Action (re-hunt and checks; never an automatic response). */
export const VERIFICATION_METHODS = {
  IOC_REHUNT: "Re-hunt the IOC (IP / domain / URL / hash / account) in Wazuh after containment.",
  RECURRENCE_CHECK: "Check whether the original detection rule / IOC recurs after containment.",
  RELATED_EVENT_CHECK: "Check whether events related to the incident continue.",
  ENDPOINT_ACTIVITY_CHECK: "Check the affected endpoint's activity (process, file, network) after containment.",
  NETWORK_ACTIVITY_CHECK: "Check network events to / from the IOC after containment.",
  AUTHENTICATION_CHECK: "Check authentication events for the account after containment (old credential use, suspicious logons).",
  SESSION_CHECK: "Check that no session of the account remains active.",
  PROCESS_CHECK: "Confirm the process no longer exists and does not restart.",
} as const;
export type VerificationMethodId = keyof typeof VERIFICATION_METHODS;
export const VERIFICATION_METHOD_IDS = Object.keys(VERIFICATION_METHODS) as VerificationMethodId[];
