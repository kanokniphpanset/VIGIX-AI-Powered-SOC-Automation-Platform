import { ATTACK_TYPES, AttackType } from "./knowledgeTypes";

/**
 * Attack-type knowledge: what each of the 10 evaluation attack types looks like, what evidence and IOCs it needs,
 * which MITRE ATT&CK techniques represent it, and which incident-level Playbook / Runbook handle it.
 *
 * The chain is  Attack Type -> Evidence -> MITRE -> Action -> Playbook -> Runbook -> Policy -> Verification:
 *   - Actions come from actionKnowledge.ts (actionsForAttackType) and equal the playbook's allowedActions;
 *   - `mitreTechniques` equal the playbook's triggerConditions.mitreTechniques (the PlaybookSelector input), so
 *     the MITRE mapping is what actually selects the playbook — no second mapping the AI could pick from;
 *   - Policies and verification methods follow from the Actions (ACTION_COMPLIANCE / APPROVAL / VERIFICATION seeds).
 * test/KnowledgeCatalog.test.ts enforces every link against the real seeds.
 *
 * `incidentType` is the playbook's incident type as stored in Postgres; BRUTE_FORCE keeps its historical
 * SSH_BRUTE_FORCE incident type (renaming it would orphan existing incidents and RG-* group policies).
 */
export interface AttackKnowledge {
  attackType: AttackType;
  name: string;
  description: string;
  detection: string[];
  requiredEvidence: string[];
  iocTypes: string[];
  mitreTechniques: string[];
  riskIndicators: string[];
  incidentType: string;
  playbook: string;
  /** Incident-level runbooks (RB-*-001) for the whole attack; action-level runbooks follow from the Actions. */
  incidentRunbooks: string[];
}

export const ATTACK_KNOWLEDGE: AttackKnowledge[] = [
  {
    attackType: "BRUTE_FORCE",
    name: "Brute Force",
    description: "Repeated authentication attempts against one or more accounts from an external source (password guessing).",
    detection: ["Many failed logons for one account / source in a short window", "Failed logons across several usernames from one source"],
    requiredEvidence: ["Failed-authentication events", "Source IP", "Targeted account", "Affected host"],
    iocTypes: ["ip", "user"],
    mitreTechniques: ["T1110", "T1110.001"],
    riskIndicators: ["Successful logon after the failures", "Privileged / root account targeted", "Source on a threat-intelligence block list"],
    incidentType: "SSH_BRUTE_FORCE",
    playbook: "PB-SSH-BRUTEFORCE",
    incidentRunbooks: ["RB-BRUTEFORCE-001"],
  },
  {
    attackType: "MALWARE",
    name: "Malware",
    description: "A malicious file or implant downloaded to / executed on an endpoint, possibly with download or C2 infrastructure.",
    detection: ["AV / EDR / FIM detection of a malicious file", "Hash match against threat intelligence", "Download from a malicious URL"],
    requiredEvidence: ["Affected endpoint", "File path and hash", "Detection event", "Download / C2 indicators when present"],
    iocTypes: ["hash", "file", "url", "domain", "ip", "process"],
    mitreTechniques: ["T1204.002", "T1105"],
    riskIndicators: ["File executed", "Outbound C2 traffic", "Persistence created", "Same hash on other endpoints"],
    incidentType: "MALWARE",
    playbook: "PB-MALWARE",
    incidentRunbooks: ["RB-MALWARE-001"],
  },
  {
    attackType: "PHISHING",
    name: "Phishing",
    description: "A malicious e-mail (link or attachment) delivered to users to steal credentials or deliver malware.",
    detection: ["Mail-gateway detection / user report", "Click on a known-malicious URL", "Credential submission to a look-alike page"],
    requiredEvidence: ["Message (sender / recipient)", "Malicious URL or domain", "Recipient account", "Click / credential-submission event when present"],
    iocTypes: ["email", "url", "domain", "user"],
    mitreTechniques: ["T1566", "T1566.001", "T1566.002"],
    riskIndicators: ["User clicked the link", "Credentials submitted", "Attachment executed", "Privileged recipient"],
    incidentType: "PHISHING",
    playbook: "PB-PHISHING",
    incidentRunbooks: ["RB-PHISHING-001"],
  },
  {
    attackType: "ACCOUNT_COMPROMISE",
    name: "Account Compromise",
    description: "Use or manipulation of a valid account by an unauthorized party (suspicious logon, group-membership change).",
    detection: ["Logon from an unusual external source", "Impossible travel / unusual hours", "Account added to a privileged group"],
    requiredEvidence: ["Account identifier", "Suspicious authentication event", "Source IP", "Affected host"],
    iocTypes: ["user", "ip"],
    mitreTechniques: ["T1078", "T1098"],
    riskIndicators: ["Privileged group membership changed", "Logon from a malicious source", "Activity after logon on critical assets"],
    incidentType: "ACCOUNT_COMPROMISE",
    playbook: "PB-ACCOUNT-COMPROMISE",
    incidentRunbooks: [],
  },
  {
    attackType: "POWERSHELL",
    name: "PowerShell Attack",
    description: "Malicious / obfuscated PowerShell execution: download cradles, encoded commands, PowerShell-based persistence.",
    detection: ["Encoded or hidden PowerShell command line", "Download cradle to an external URL", "Run-key persistence created by PowerShell"],
    requiredEvidence: ["Affected endpoint", "PowerShell process and command line", "Stager / C2 URL, domain or IP when present"],
    iocTypes: ["command", "process", "url", "domain", "ip", "registry", "user"],
    mitreTechniques: ["T1059.001", "T1547.001"],
    riskIndicators: ["Encoded command", "Network download", "Persistence created", "Office application as parent"],
    incidentType: "POWERSHELL",
    playbook: "PB-POWERSHELL",
    incidentRunbooks: [],
  },
  {
    attackType: "SQL_INJECTION",
    name: "SQL Injection",
    description: "SQL injection attempts against a public-facing web application.",
    detection: ["WAF / web-log detection of SQL patterns (UNION, ' OR 1=1, comment sequences)", "Authentication-bypass probe"],
    requiredEvidence: ["Source IP", "Malicious request", "Targeted web host"],
    iocTypes: ["ip", "request"],
    mitreTechniques: ["T1190"],
    riskIndicators: ["HTTP 200 on an injection request", "Several web hosts targeted", "Data returned in the response"],
    incidentType: "SQL_INJECTION",
    playbook: "PB-SQL-INJECTION",
    incidentRunbooks: [],
  },
  {
    attackType: "COMMAND_AND_CONTROL",
    name: "Command & Control (C2)",
    description: "An endpoint communicating with attacker infrastructure (beaconing over an application-layer or encrypted channel).",
    detection: ["Periodic outbound connections (beaconing)", "Connection to a destination on a threat-intelligence list", "Traffic on a non-standard port"],
    requiredEvidence: ["Affected endpoint", "Destination IP / domain", "Network event"],
    iocTypes: ["ip", "domain", "url"],
    mitreTechniques: ["T1071", "T1573", "T1571"],
    riskIndicators: ["Regular beacon interval", "Destination reputation malicious", "Several endpoints contacting the same destination"],
    incidentType: "COMMAND_AND_CONTROL",
    playbook: "PB-C2",
    incidentRunbooks: ["RB-NETWORK-001"],
  },
  {
    attackType: "SUSPICIOUS_PROCESS_EXECUTION",
    name: "Suspicious Process Execution",
    description: "Suspicious process execution through a command shell or a signed system binary (LOLBin) proxying execution.",
    detection: ["Shell spawned by an unusual parent", "System binary (rundll32 / regsvr32 / mshta) executing a payload", "Execution from a user-writable path"],
    requiredEvidence: ["Affected endpoint", "Process and command line", "File path / hash of the executed payload"],
    iocTypes: ["process", "command", "file", "hash"],
    mitreTechniques: ["T1059.003", "T1059.004", "T1218"],
    riskIndicators: ["Unusual parent-child chain", "Execution from a temp / download folder", "Network activity by the process"],
    incidentType: "SUSPICIOUS_PROCESS_EXECUTION",
    playbook: "PB-SUSPICIOUS-PROCESS",
    incidentRunbooks: [],
  },
  {
    attackType: "DATA_EXFILTRATION",
    name: "Data Exfiltration",
    description: "Data leaving the environment over a C2 channel, an alternative protocol or a web service.",
    detection: ["Unusually large outbound transfer", "Upload to a cloud storage / paste service", "Outbound transfer over an unusual protocol"],
    requiredEvidence: ["Source endpoint", "Destination IP / domain / URL", "Network / transfer event"],
    iocTypes: ["ip", "domain", "url", "user"],
    mitreTechniques: ["T1041", "T1048", "T1567"],
    riskIndicators: ["Volume far above baseline", "Regulated / customer data involved", "Transfer outside business hours"],
    incidentType: "DATA_EXFILTRATION",
    playbook: "PB-DATA-EXFIL",
    incidentRunbooks: ["RB-NETWORK-001"],
  },
  {
    attackType: "PRIVILEGE_ESCALATION",
    name: "Privilege Escalation",
    description: "A user or process gaining higher privileges by exploiting a vulnerability or abusing an elevation mechanism (e.g. sudo).",
    detection: ["Unauthorized sudo attempt", "Privileged activity by a non-admin user", "Exploit of a local vulnerability"],
    requiredEvidence: ["Account identifier", "Affected endpoint", "Elevation event (sudo / exploit)", "Process of the elevated activity when present"],
    iocTypes: ["user", "process", "command"],
    mitreTechniques: ["T1068", "T1548"],
    riskIndicators: ["Elevation succeeded", "Root / SYSTEM shell", "Critical asset"],
    incidentType: "PRIVILEGE_ESCALATION",
    playbook: "PB-PRIV-ESC",
    incidentRunbooks: [],
  },
];

export const findAttackKnowledge = (attackType: string): AttackKnowledge | undefined => ATTACK_KNOWLEDGE.find((a) => a.attackType === attackType);

/** Attack type of a playbook incident type (SSH_BRUTE_FORCE -> BRUTE_FORCE); null for a type with no knowledge. */
export function attackTypeForIncidentType(incidentType: string | null | undefined): AttackType | null {
  if (!incidentType) return null;
  const k = ATTACK_KNOWLEDGE.find((a) => a.incidentType === incidentType) ?? ATTACK_KNOWLEDGE.find((a) => a.attackType === incidentType);
  return k && (ATTACK_TYPES as readonly string[]).includes(k.attackType) ? k.attackType : null;
}
