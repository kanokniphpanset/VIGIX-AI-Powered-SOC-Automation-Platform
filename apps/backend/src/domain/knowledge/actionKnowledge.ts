import { AttackType, EvidenceRequirementId, TargetKind, VerificationMethodId } from "./knowledgeTypes";

/**
 * Structured knowledge for every Action Catalog entry (prisma/seeds/action.seed.ts seeds the rows; this is what the
 * Action row's free-text description cannot carry). The Action Catalog row stays the authority for existence,
 * enabled/disabled, impact level and the runbook link; this file is the authority for:
 *   - targetKind:            the kind of recorded value the Action operates on (RecommendationValidator);
 *   - applicableAttackTypes: the attack types it may be recommended for (RecommendationValidator — a playbook that
 *                            lists an inapplicable Action is rejected; test/KnowledgeCatalog.test.ts keeps the seeds
 *                            consistent);
 *   - requiredEvidence:      deterministic evidence checks (ActionEvidence.ts). Policy (ACTION_COMPLIANCE) can add
 *                            more requirements on top; it can never remove these;
 *   - analystConfirmed:      evidence the recorded data cannot prove — a precondition IR confirms in the runbook;
 *   - verification:          how an executed Action is verified (re-hunt / checks, never an automatic response).
 *
 * Applicability of the pre-existing Actions is the union of the attack types named in their catalog description and
 * the incident-level playbooks that already allowed them (those playbooks are kept unchanged). The six Actions added
 * for the evaluation suite follow the Knowledge Expansion spec exactly.
 */
export interface ActionKnowledge {
  code: string;
  name: string;
  category: "CONTAINMENT" | "INVESTIGATION" | "VERIFICATION";
  targetKind: TargetKind | null;
  applicableAttackTypes: AttackType[];
  requiredEvidence: EvidenceRequirementId[];
  analystConfirmed: string[];
  expectedEffect: string;
  verification: VerificationMethodId[];
  /** Action-level runbook (RB-*) — the operational procedure the Recommendation expands. */
  runbook: string | null;
}

export const ACTION_KNOWLEDGE: ActionKnowledge[] = [
  // ---- Pre-existing Action Catalog entries ---------------------------------------------------------------------
  {
    code: "ACT-BLOCK-SOURCE-IP",
    name: "Block Source IP",
    category: "CONTAINMENT",
    targetKind: "ip",
    applicableAttackTypes: ["BRUTE_FORCE", "SQL_INJECTION", "MALWARE", "POWERSHELL", "ACCOUNT_COMPROMISE"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "SUPPORTING_EVIDENCE"],
    analystConfirmed: ["The source has no legitimate business reason to reach the affected host/service."],
    expectedEffect: "Reduce or prevent further communication from the identified source.",
    verification: ["IOC_REHUNT", "RELATED_EVENT_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-BLOCK-SOURCE-IP",
  },
  {
    code: "ACT-DISABLE-ACCOUNT",
    name: "Disable User Account",
    category: "CONTAINMENT",
    targetKind: "account",
    applicableAttackTypes: ["BRUTE_FORCE", "PHISHING", "ACCOUNT_COMPROMISE", "POWERSHELL", "PRIVILEGE_ESCALATION", "DATA_EXFILTRATION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT"],
    analystConfirmed: ["Suspicious authentication or compromise evidence for the account."],
    expectedEffect: "Prevent further authentication using the affected account.",
    verification: ["AUTHENTICATION_CHECK", "RELATED_EVENT_CHECK"],
    runbook: "RB-DISABLE-ACCOUNT",
  },
  {
    code: "ACT-ISOLATE-ENDPOINT",
    name: "Isolate Endpoint",
    category: "CONTAINMENT",
    targetKind: "host",
    applicableAttackTypes: [
      "MALWARE",
      "PHISHING",
      "ACCOUNT_COMPROMISE",
      "POWERSHELL",
      "COMMAND_AND_CONTROL",
      "SUSPICIOUS_PROCESS_EXECUTION",
      "DATA_EXFILTRATION",
      "PRIVILEGE_ESCALATION",
    ],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "AFFECTED_ENDPOINT", "SUSPICIOUS_ACTIVITY_EVIDENCE"],
    analystConfirmed: ["Evidence supports compromise of the endpoint."],
    expectedEffect: "Reduce communication from the affected endpoint and limit potential spread.",
    verification: ["ENDPOINT_ACTIVITY_CHECK", "NETWORK_ACTIVITY_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-ISOLATE-ENDPOINT",
  },
  {
    code: "ACT-BLOCK-DOMAIN",
    name: "Block Domain",
    category: "CONTAINMENT",
    targetKind: "domain",
    applicableAttackTypes: ["PHISHING", "MALWARE", "POWERSHELL", "COMMAND_AND_CONTROL", "DATA_EXFILTRATION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "SUPPORTING_EVIDENCE"],
    analystConfirmed: ["The domain is not a shared or legitimate service domain."],
    expectedEffect: "Reduce communication with the identified domain.",
    verification: ["IOC_REHUNT", "NETWORK_ACTIVITY_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-BLOCK-DOMAIN",
  },
  {
    code: "ACT-BLOCK-URL",
    name: "Block URL",
    category: "CONTAINMENT",
    targetKind: "url",
    applicableAttackTypes: ["PHISHING", "MALWARE", "POWERSHELL", "COMMAND_AND_CONTROL", "DATA_EXFILTRATION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "SUPPORTING_EVIDENCE"],
    analystConfirmed: [],
    expectedEffect: "Reduce access to the identified malicious resource.",
    verification: ["IOC_REHUNT", "NETWORK_ACTIVITY_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-BLOCK-URL",
  },
  {
    code: "ACT-QUARANTINE-EMAIL",
    name: "Quarantine Email",
    category: "CONTAINMENT",
    targetKind: "email",
    applicableAttackTypes: ["PHISHING"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT"],
    analystConfirmed: ["Message id, sender and recipients of the malicious message."],
    expectedEffect: "Reduce additional user interaction with the malicious message.",
    verification: ["IOC_REHUNT", "RECURRENCE_CHECK"],
    runbook: "RB-QUARANTINE-EMAIL",
  },
  {
    code: "ACT-007",
    name: "Collect Evidence",
    category: "INVESTIGATION",
    targetKind: null,
    applicableAttackTypes: [],
    requiredEvidence: ["AFFECTED_ENDPOINT"],
    analystConfirmed: [],
    expectedEffect: "Forensic evidence of the affected host is preserved for investigation.",
    verification: ["ENDPOINT_ACTIVITY_CHECK"],
    runbook: null,
  },
  {
    code: "ACT-008",
    name: "Re-hunt IOC",
    category: "VERIFICATION",
    targetKind: null,
    applicableAttackTypes: [],
    requiredEvidence: ["SUPPORTING_EVIDENCE"],
    analystConfirmed: [],
    expectedEffect: "Containment / eradication is confirmed or a recurrence is detected.",
    verification: ["IOC_REHUNT", "RECURRENCE_CHECK"],
    runbook: null,
  },

  // ---- Added by the Knowledge Expansion for Evaluation spec --------------------------------------------------------
  {
    code: "ACT-QUARANTINE-FILE",
    name: "Quarantine File",
    category: "CONTAINMENT",
    targetKind: "file",
    applicableAttackTypes: ["MALWARE", "POWERSHELL", "SUSPICIOUS_PROCESS_EXECUTION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "AFFECTED_ENDPOINT", "FILE_HASH", "SUSPICIOUS_ACTIVITY_EVIDENCE"],
    analystConfirmed: ["Supporting malicious evidence for the file (detection / threat intelligence verdict)."],
    expectedEffect: "Prevent execution or further use of the identified malicious file.",
    verification: ["IOC_REHUNT", "RECURRENCE_CHECK", "ENDPOINT_ACTIVITY_CHECK"],
    runbook: "RB-QUARANTINE-FILE",
  },
  {
    code: "ACT-KILL-PROCESS",
    name: "Terminate Malicious Process",
    category: "CONTAINMENT",
    targetKind: "process",
    applicableAttackTypes: ["MALWARE", "POWERSHELL", "SUSPICIOUS_PROCESS_EXECUTION", "PRIVILEGE_ESCALATION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "AFFECTED_ENDPOINT", "COMMAND_LINE", "SUSPICIOUS_ACTIVITY_EVIDENCE"],
    analystConfirmed: ["PID of the running process on the endpoint.", "Supporting malicious evidence for the process."],
    expectedEffect: "Terminate the identified malicious process.",
    verification: ["PROCESS_CHECK", "IOC_REHUNT", "RECURRENCE_CHECK"],
    runbook: "RB-KILL-MALICIOUS-PROCESS",
  },
  {
    code: "ACT-RESET-CREDENTIAL",
    name: "Reset User Credentials",
    category: "CONTAINMENT",
    targetKind: "account",
    applicableAttackTypes: ["ACCOUNT_COMPROMISE", "PHISHING", "BRUTE_FORCE", "SQL_INJECTION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "AUTHENTICATION_EVIDENCE"],
    analystConfirmed: ["Evidence of credential compromise (successful suspicious logon, credential submitted to a phishing page)."],
    expectedEffect: "Invalidate compromised credentials and require new credentials.",
    verification: ["AUTHENTICATION_CHECK", "RELATED_EVENT_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-RESET-CREDENTIAL",
  },
  {
    code: "ACT-REVOKE-SESSION",
    name: "Revoke Active Sessions",
    category: "CONTAINMENT",
    targetKind: "account",
    applicableAttackTypes: ["ACCOUNT_COMPROMISE", "PHISHING", "BRUTE_FORCE", "DATA_EXFILTRATION", "PRIVILEGE_ESCALATION", "SQL_INJECTION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "AUTHENTICATION_EVIDENCE"],
    analystConfirmed: ["Active or suspicious session of the account."],
    expectedEffect: "Terminate active sessions associated with the affected account.",
    verification: ["SESSION_CHECK", "AUTHENTICATION_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-REVOKE-SESSION",
  },
  {
    code: "ACT-BLOCK-HASH",
    name: "Block File Hash",
    category: "CONTAINMENT",
    targetKind: "hash",
    applicableAttackTypes: ["MALWARE", "POWERSHELL", "SUSPICIOUS_PROCESS_EXECUTION", "PHISHING", "COMMAND_AND_CONTROL"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "SUPPORTING_EVIDENCE"],
    analystConfirmed: ["Supporting malicious evidence for the hash (detection / threat intelligence verdict)."],
    expectedEffect: "Prevent execution or detection of the identified malicious file hash.",
    verification: ["IOC_REHUNT", "RECURRENCE_CHECK"],
    runbook: "RB-BLOCK-HASH",
  },
  {
    code: "ACT-BLOCK-DESTINATION-IP",
    name: "Block Destination IP",
    category: "CONTAINMENT",
    targetKind: "ip",
    applicableAttackTypes: ["COMMAND_AND_CONTROL", "DATA_EXFILTRATION", "MALWARE"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "SUPPORTING_EVIDENCE"],
    analystConfirmed: ["Supporting IOC / CTI evidence that the destination is malicious."],
    expectedEffect: "Prevent communication to the identified destination IP.",
    verification: ["IOC_REHUNT", "NETWORK_ACTIVITY_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-C2-CONTAINMENT",
  },

  // ---- Attack-specific containment procedures (knowledge/playbooks/PB-STC-001/procedures/*/containment.yaml) ------
  // Added only where a procedure needs a containment control no existing Action provides. Revoking a token reuses
  // ACT-REVOKE-SESSION, removing an e-mail reuses ACT-QUARANTINE-EMAIL and blocking a destination domain reuses
  // ACT-BLOCK-DOMAIN. Checks (identify source, check successful login, monitor, check persistence) are never Actions.
  {
    code: "ACT-RATE-LIMIT-SOURCE",
    name: "Rate-Limit Source",
    category: "CONTAINMENT",
    targetKind: "ip",
    applicableAttackTypes: ["BRUTE_FORCE", "SQL_INJECTION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "SUPPORTING_EVIDENCE"],
    analystConfirmed: ["The source keeps sending repeated authentication attempts or malicious requests."],
    expectedEffect: "Throttle repeated authentication attempts or malicious requests from the identified source.",
    verification: ["IOC_REHUNT", "RELATED_EVENT_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-RATE-LIMIT-SOURCE",
  },
  {
    code: "ACT-BLOCK-SENDER",
    name: "Block Sender",
    category: "CONTAINMENT",
    targetKind: "email",
    applicableAttackTypes: ["PHISHING"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "EMAIL_MESSAGE"],
    analystConfirmed: ["The sender is confirmed malicious (not a compromised partner mailbox that must stay reachable)."],
    expectedEffect: "Prevent further delivery of messages from the identified sender.",
    verification: ["IOC_REHUNT", "RECURRENCE_CHECK"],
    runbook: "RB-BLOCK-SENDER",
  },
  {
    code: "ACT-REMOVE-PRIVILEGE",
    name: "Remove Unauthorized Privilege",
    category: "CONTAINMENT",
    targetKind: "account",
    applicableAttackTypes: ["PRIVILEGE_ESCALATION"],
    requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "AUTHENTICATION_EVIDENCE"],
    analystConfirmed: ["The privilege assignment is not authorized through change management."],
    expectedEffect: "Return the account's privileges to the approved baseline.",
    verification: ["AUTHENTICATION_CHECK", "RELATED_EVENT_CHECK", "RECURRENCE_CHECK"],
    runbook: "RB-REMOVE-PRIVILEGE",
  },
];

export const findActionKnowledge = (code: string): ActionKnowledge | undefined => ACTION_KNOWLEDGE.find((a) => a.code === code);

/** Containment Actions that may be recommended for an attack type (the playbook of that type allows exactly these). */
export const actionsForAttackType = (attackType: AttackType): string[] =>
  ACTION_KNOWLEDGE.filter((a) => a.category === "CONTAINMENT" && a.applicableAttackTypes.includes(attackType)).map((a) => a.code);
