/**
 * Evidence signals — deterministic facts derived ONLY from what the incident recorded (alert titles, IOCs, MITRE
 * techniques the SIEM / MitreAgent mapped). A procedure step may declare `appliesWhenSignals`; it is then offered
 * only when at least one of those signals is present, so a response never contains a step the evidence does not
 * support (e.g. credential reset after failed logins only). A signal is "the evidence says so", never "the AI
 * assumed so": the AI cannot add a signal and the validator re-derives them from the same context.
 *
 * The same table drives UNSUPPORTED_ASSUMPTION in RecommendationValidator: prose that asserts a compromise,
 * breach or malicious execution is rejected while the matching signal is absent.
 */
export const EVIDENCE_SIGNALS = [
  "SUCCESSFUL_LOGIN",
  "USER_CLICKED",
  "CREDENTIAL_SUBMITTED",
  "PAYLOAD_EXECUTED",
  "MALICIOUS_EXECUTION",
  "C2_COMMUNICATION",
  "DATA_TRANSFER_ANOMALY",
  "LATERAL_MOVEMENT",
  "DATABASE_IMPACT",
] as const;
export type EvidenceSignal = (typeof EVIDENCE_SIGNALS)[number];

export interface SignalInput {
  mitreMappings: { techniqueId: string }[];
  evidence?: { title: string }[];
  iocs?: { iocType: string; iocValue: string; reputationScore?: number | null }[];
  incidentTitle?: string;
}

interface SignalRule {
  signal: EvidenceSignal;
  text?: RegExp;
  techniques?: string[];
  iocValue?: RegExp;
  maliciousReputation?: boolean;
}

const RULES: SignalRule[] = [
  { signal: "SUCCESSFUL_LOGIN", text: /\b(?:successful(?:ly)?|accepted)\s+(?:ssh\s+|remote\s+)?(?:log-?in|log-?on|authentication|password|publickey)|\b(?:log-?in|log-?on|authentication)\s+(?:was\s+)?success|\blogged in\b|\bevent\s*4624\b/i, techniques: ["T1078"] },
  { signal: "USER_CLICKED", text: /\b(?:clicked|click(?:ed)? through|opened the (?:link|url)|visited the (?:phishing|malicious))\b/i },
  { signal: "CREDENTIAL_SUBMITTED", text: /\bcredentials?\s+(?:were\s+|was\s+|have been\s+)?(?:submitted|entered|typed)\b|\b(?:submitted|entered)\s+(?:his |her |their |the )?(?:credentials?|password)\b/i },
  { signal: "PAYLOAD_EXECUTED", text: /\b(?:attachment|payload|macro|executable|file)\s+(?:was\s+)?(?:opened|executed|ran|launched|detonated)\b|\bexecuted the (?:attachment|payload|file)\b/i, techniques: ["T1204.002"] },
  {
    signal: "MALICIOUS_EXECUTION",
    text: /(?<!non-)(?<!not )(?<!un)\bmalicious\b|\bencoded\b|\bobfuscat|\bdownload cradle\b|\bbase64\b|\bbeacon|\bdownloadstring\b|\biex\b|-enc(?:odedcommand)?\b|\|\s*(?:ba)?sh\b/i,
    iocValue: /base64\s+-d|\|\s*(?:ba)?sh\b|-enc(?:odedcommand)?\s|downloadstring|invoke-expression/i,
    maliciousReputation: true,
  },
  { signal: "C2_COMMUNICATION", text: /\bc2\b|\bcommand[- ]and[- ]control\b|\bbeaconing?\b/i, techniques: ["T1071", "T1573", "T1095", "T1105"] },
  { signal: "DATA_TRANSFER_ANOMALY", text: /\b(?:large|abnormal|unusual)\s+(?:outbound\s+)?(?:upload|transfer)\b|\boutbound (?:upload|transfer)\b|\bexfiltrat/i, techniques: ["T1048", "T1041", "T1567"] },
  { signal: "LATERAL_MOVEMENT", text: /\blateral movement\b|\bpsexec\b|\bremote (?:service|execution)\b/i, techniques: ["T1021", "T1570"] },
  { signal: "DATABASE_IMPACT", text: /\b(?:data|database|records?|tables?)\s+(?:was\s+|were\s+)?(?:read|dumped|exported|modified|deleted)\b|\binformation_schema enumeration\b/i },
];

const matchesTechnique = (mapped: string[], wanted: string[]) => mapped.some((m) => wanted.some((w) => m === w || m.startsWith(`${w}.`)));

export function deriveEvidenceSignals(input: SignalInput): Set<EvidenceSignal> {
  const texts = [input.incidentTitle ?? "", ...(input.evidence ?? []).map((e) => e.title)];
  const techniques = input.mitreMappings.map((m) => m.techniqueId);
  const out = new Set<EvidenceSignal>();
  for (const rule of RULES) {
    const hit =
      (rule.text && texts.some((t) => rule.text!.test(t))) ||
      (rule.techniques && matchesTechnique(techniques, rule.techniques)) ||
      (rule.iocValue && (input.iocs ?? []).some((i) => rule.iocValue!.test(i.iocValue))) ||
      (rule.maliciousReputation && (input.iocs ?? []).some((i) => (i.reputationScore ?? 0) >= 70));
    if (hit) out.add(rule.signal);
  }
  return out;
}

/**
 * Prose that asserts a fact the evidence has not established. `requires` lists signals of which at least one must be
 * present for the sentence to be allowed; `types` lists attack types for which the incident itself is the assertion
 * (an ACCOUNT_COMPROMISE incident may say "account compromised").
 */
export interface AssumptionRule {
  id: string;
  pattern: RegExp;
  requires: EvidenceSignal[];
  types: string[];
  claim: string;
}

export const ASSUMPTION_RULES: AssumptionRule[] = [
  { id: "ACCOUNT_COMPROMISED", pattern: /\b(?:account|credentials?|password)\b[^.]{0,30}\b(?:is|was|were|has been|have been|are)\s+(?:confirmed\s+)?(?:compromised|stolen)\b|\bcompromised (?:account|credentials?)\b/i, requires: ["SUCCESSFUL_LOGIN", "CREDENTIAL_SUBMITTED"], types: ["ACCOUNT_COMPROMISE", "PRIVILEGE_ESCALATION"], claim: "account / credential compromise" },
  { id: "DATA_BREACH", pattern: /\b(?:data\s+)?(?:breach|exfiltration)\s+(?:is |was |has been )?confirmed\b|\bconfirmed\s+(?:data\s+)?(?:breach|exfiltration)\b|\bdata\s+(?:was|were|has been)\s+(?:stolen|exfiltrated|leaked)\b/i, requires: ["DATA_TRANSFER_ANOMALY"], types: ["DATA_EXFILTRATION"], claim: "data breach / exfiltration" },
  { id: "INJECTION_SUCCEEDED", pattern: /\b(?:injection|sqli|attack)\s+(?:was\s+|has been\s+)?(?:successful|succeeded)\b|\bdatabase\s+(?:was\s+|has been\s+)?(?:compromised|breached)\b/i, requires: ["DATABASE_IMPACT"], types: [], claim: "a successful injection / database compromise" },
  { id: "MALICIOUS_CONFIRMED", pattern: /\b(?:confirmed|verified)\s+(?:as\s+)?malicious\s+(?:process|execution|powershell|script)\b|\bis\s+(?:a\s+)?(?:confirmed\s+)?malware\b/i, requires: ["MALICIOUS_EXECUTION", "PAYLOAD_EXECUTED"], types: ["MALWARE", "COMMAND_AND_CONTROL"], claim: "confirmed malicious execution" },
];

/** Controls that belong to ONE attack family; copying them into another family's response is rejected. */
export interface AttackControlRule {
  id: string;
  pattern: RegExp;
  onlyFor: string[];
  description: string;
}

export const ATTACK_SPECIFIC_CONTROLS: AttackControlRule[] = [
  { id: "WEB_APPLICATION_CONTROL", pattern: /\bWAF rule\b|\bparameteri[sz]ed quer|\bprepared statement|\binjectable\b|\bvulnerable (?:web )?(?:parameter|endpoint)\b|\bvirtual patch\b/i, onlyFor: ["SQL_INJECTION"], description: "web-application / SQL injection control" },
  { id: "DATABASE_REMEDIATION", pattern: /\bdatabase (?:audit|query) logs?\b|\bleast privilege\b[^.]{0,40}\bdatabase\b|\bdatabase account'?s? privileges\b/i, onlyFor: ["SQL_INJECTION"], description: "database remediation" },
];
