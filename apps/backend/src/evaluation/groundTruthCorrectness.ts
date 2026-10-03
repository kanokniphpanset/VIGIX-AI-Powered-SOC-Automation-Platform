/**
 * groundTruthCorrectness.ts - Action -> Target Ground Truth for the "Correct Recommendation" metric (v3.3).
 *
 * DERIVATION RULE (fixed before any v3 run; no AI output, no v2 result, no validator/compliance/consistency output used):
 *   For each case, every action in groundTruthReal.ts `expectedActions` is paired with the `expectedTargets` whose
 *   TargetKind equals the Action Catalog's `targetKind` for that action (domain/knowledge/actionKnowledge.ts).
 *   An `expectedTargets` value for which no expected action of the matching kind exists is NOT an expected target
 *   (it stays "acceptable evidence", e.g. `attack-endpoint` when ISOLATE-ENDPOINT is not an expected action).
 *   An action that is not in `expectedActions` is UNEXPECTED, even if it is in `allowedActions`.
 *   No optional recommendations are defined (strict). Values with "@NAME" are environment facts resolved before the
 *   attack, exactly as in groundTruthReal.ts.
 *
 * v3.1 (prepared BEFORE any v3 run; no AI output, no v2/v3 result used): TC-04 and TC-08 additionally expect the
 * actions that the case's incident playbook (prisma/seeds/playbook.seed.ts) lists as an UNCONDITIONAL standard step
 * and whose target is already an `expectedTargets` value of the case:
 *   TC-04  PB-ACCOUNT-COMPROMISE step 2  ACT-BLOCK-SOURCE-IP -> @ATTACKER_IP    ("Block the external source IP of the suspicious logon")
 *   TC-08  PB-SUSPICIOUS-PROCESS step 2  ACT-BLOCK-HASH       -> @KWORKERD_SHA256 ("Quarantine the payload file and block its hash")
 * Conditional steps ("only if / when evidence shows ...", e.g. ISOLATE-ENDPOINT in TC-04 and TC-08) are NOT expected: there
 * is no scenario evidence that the condition holds.
 *
 * v3.2 (prepared BEFORE any v3 run; no AI output, no v2/v3 result used): TC-02 additionally expects
 *   TC-02  PB-MALWARE step 1  ACT-ISOLATE-ENDPOINT -> attack-endpoint ("Isolate the affected endpoint recorded in the evidence")
 * because the step is unconditional, the Action Catalog targetKind of ISOLATE-ENDPOINT is `host` (the only host-kind action in
 * PB-MALWARE allowedActions), and `attack-endpoint` is the Wazuh agent / monitored endpoint of the TC-02 simulation and was
 * already listed in the TC-02 `expectedTargets`, frozen on 2026-09-30 (run.json groundTruthFrozenAt) before any v2/v3 output.
 *
 * v3.3 (prepared BEFORE any v3 run; no AI output, no v2/v3 result used): TC-05 (PowerShell) is added from a controlled
 * REAL_WAZUH scenario (Windows 10 + Wazuh agent 4.9.2 + Sysmon 15.22): powershell.exe resolves the reserved-TLD lab name
 * vigix-eval-ps-stager.test -> Sysmon event 22 -> custom Wazuh rule 100300 (level 12, MITRE T1059.001). Expected pair:
 *   TC-05  PB-POWERSHELL step 2  ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test  (target: data.win.eventdata.queryName)
 * ACT-ISOLATE-ENDPOINT -> vigix-win10-ps is NOT expected: the scenario proves PowerShell/DNS activity but not that the
 * endpoint was compromised. The mock TC-05 file is not used. groundTruthReal.ts is unchanged, so TC-05 is still marked
 * ENVIRONMENT_UNAVAILABLE there until that case is wired into the real-evaluation harness (a separate step).
 *
 * No Action, Playbook or Policy is added: `CorrectRecommendation.test.ts` asserts that every playbook, action and target
 * below already exists in groundTruthReal.ts / the Action Catalog / the playbook seed, that every pair satisfies the
 * targetKind rule, and that each playbook-sourced pair comes from an unconditional step. groundTruthReal.ts is unchanged,
 * so the v2 Ground Truth hash (e54d0035...) remains valid.
 */
import { createHash } from "crypto";
import { CorrectnessGroundTruth } from "./correctRecommendation";

export const CORRECTNESS_GT_VERSION = "correctness-gt-v3.3";

export const CORRECTNESS_GROUND_TRUTH: CorrectnessGroundTruth[] = [
  {
    caseId: "TC-01", expectedPlaybook: "PB-SSH-BRUTEFORCE",
    expectedRecommendations: [
      { action: "ACT-BLOCK-SOURCE-IP", targets: [{ type: "ip", value: "@ATTACKER_IP" }], rationale: "SSH brute force from the attacker address: contain the source." },
    ],
  },
  {
    caseId: "TC-02", expectedPlaybook: "PB-MALWARE",
    expectedRecommendations: [
      { action: "ACT-QUARANTINE-FILE", targets: [{ type: "file", value: "/root/Downloads/Invoice_Q4_2026.xls.exe" }], rationale: "Malicious file dropped on the endpoint: quarantine that file." },
      { action: "ACT-BLOCK-HASH", targets: [{ type: "hash", value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" }], rationale: "Block the known-malicious file hash." },
      { action: "ACT-ISOLATE-ENDPOINT", targets: [{ type: "host", value: "attack-endpoint" }], rationale: "Playbook standard step 1: isolate the affected endpoint recorded in the evidence.", source: { kind: "PLAYBOOK_STANDARD_STEP", playbook: "PB-MALWARE", stepOrder: 1 } },
    ],
  },
  {
    caseId: "TC-03", expectedPlaybook: "PB-PHISHING",
    expectedRecommendations: [
      { action: "ACT-BLOCK-URL", targets: [{ type: "url", value: "http://vigix-eval-phish.net/o365/verify?id=hr.clerk" }], rationale: "Credential-harvesting link." },
      { action: "ACT-BLOCK-DOMAIN", targets: [{ type: "domain", value: "vigix-eval-phish.net" }], rationale: "Phishing domain." },
      { action: "ACT-QUARANTINE-EMAIL", targets: [{ type: "email", value: "it-support@vigix-eval-phish.net" }], rationale: "Delivered phishing e-mail." },
    ],
  },
  {
    caseId: "TC-04", expectedPlaybook: "PB-ACCOUNT-COMPROMISE",
    expectedRecommendations: [
      { action: "ACT-DISABLE-ACCOUNT", targets: [{ type: "account", value: "victim" }], rationale: "Compromised account." },
      { action: "ACT-RESET-CREDENTIAL", targets: [{ type: "account", value: "victim" }], rationale: "Credentials of the compromised account." },
      { action: "ACT-BLOCK-SOURCE-IP", targets: [{ type: "ip", value: "@ATTACKER_IP" }], rationale: "Playbook standard step 2: block the external source IP of the suspicious logon.", source: { kind: "PLAYBOOK_STANDARD_STEP", playbook: "PB-ACCOUNT-COMPROMISE", stepOrder: 2 } },
    ],
  },
  {
    caseId: "TC-05", expectedPlaybook: "PB-POWERSHELL",
    expectedRecommendations: [
      {
        action: "ACT-BLOCK-DOMAIN", targets: [{ type: "domain", value: "vigix-eval-ps-stager.test" }],
        rationale: "Playbook standard step 2: block the stager/C2 domain recorded in the evidence. REAL_WAZUH scenario: Sysmon event 22 queryName, rule 100300 L12 T1059.001.",
        source: {
          kind: "PLAYBOOK_STANDARD_STEP", playbook: "PB-POWERSHELL", stepOrder: 2,
          targetFrom: { kind: "REAL_WAZUH_SCENARIO", ruleId: "100300", field: "data.win.eventdata.queryName" },
        },
      },
    ],
  },
  {
    caseId: "TC-06", expectedPlaybook: "PB-SQL-INJECTION",
    expectedRecommendations: [
      { action: "ACT-BLOCK-SOURCE-IP", targets: [{ type: "ip", value: "@ATTACKER_IP" }], rationale: "SQL injection source." },
    ],
  },
  {
    caseId: "TC-07", expectedPlaybook: "PB-C2",
    expectedRecommendations: [
      { action: "ACT-BLOCK-DOMAIN", targets: [{ type: "domain", value: "vigix-eval-c2.net" }], rationale: "C2 domain." },
      { action: "ACT-BLOCK-DESTINATION-IP", targets: [{ type: "ip", value: "@TESTSERVER_IP" }], rationale: "C2 server address (the destination of the beaconing)." },
    ],
  },
  {
    caseId: "TC-08", expectedPlaybook: "PB-SUSPICIOUS-PROCESS",
    expectedRecommendations: [
      { action: "ACT-KILL-PROCESS", targets: [{ type: "process", value: "/tmp/.cache/kworkerd" }], rationale: "Suspicious running process." },
      { action: "ACT-QUARANTINE-FILE", targets: [{ type: "file", value: "/tmp/.cache/kworkerd" }], rationale: "Binary of the suspicious process." },
      { action: "ACT-BLOCK-HASH", targets: [{ type: "hash", value: "@KWORKERD_SHA256" }], rationale: "Playbook standard step 2: quarantine the payload file and block its hash.", source: { kind: "PLAYBOOK_STANDARD_STEP", playbook: "PB-SUSPICIOUS-PROCESS", stepOrder: 2 } },
    ],
  },
  {
    caseId: "TC-09", expectedPlaybook: "PB-DATA-EXFIL",
    expectedRecommendations: [
      { action: "ACT-BLOCK-DOMAIN", targets: [{ type: "domain", value: "vigix-eval-exfil.net" }], rationale: "Exfiltration domain." },
      { action: "ACT-BLOCK-DESTINATION-IP", targets: [{ type: "ip", value: "@TESTSERVER_IP" }], rationale: "Exfiltration server address (the destination of the transfer)." },
    ],
  },
  {
    caseId: "TC-10", expectedPlaybook: "PB-ACCOUNT-COMPROMISE",
    expectedRecommendations: [
      { action: "ACT-DISABLE-ACCOUNT", targets: [{ type: "account", value: "evaluser" }], rationale: "Account that was added to a privileged group." },
    ],
  },
];

export const correctnessGroundTruthByCase = (caseId: string): CorrectnessGroundTruth | undefined =>
  CORRECTNESS_GROUND_TRUTH.find((g) => g.caseId === caseId);

/** Hash of the unresolved Ground Truth table (free-text rationales excluded so wording edits cannot masquerade as a change of expectation; provenance `source` included). */
export function correctnessGroundTruthSha256(): string {
  const canonical = CORRECTNESS_GROUND_TRUTH.map((g) => ({
    caseId: g.caseId, expectedPlaybook: g.expectedPlaybook,
    expectedRecommendations: g.expectedRecommendations.map((r) => ({ action: r.action, optional: !!r.optional, targets: r.targets, source: r.source ?? { kind: "GROUND_TRUTH_EXPECTED_ACTION" } })),
  }));
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

/** Substitute "@NAME" environment facts known BEFORE the attack (never AI output). */
export function resolveCorrectnessGroundTruth(gt: CorrectnessGroundTruth, ctx: Record<string, string>): CorrectnessGroundTruth {
  const sub = (v: string) => (v.startsWith("@") ? ctx[v.slice(1)] ?? v : v);
  return { ...gt, expectedRecommendations: gt.expectedRecommendations.map((r) => ({ ...r, targets: r.targets.map((t) => ({ ...t, value: sub(t.value) })) })) };
}

export const CORRECTNESS_GT_SOURCE = "apps/backend/src/evaluation/groundTruthCorrectness.ts";
export const CORRECTNESS_GT_RULE =
  "strict set of (action,target); playbook must match; every expected pair present; any unexpected pair => INCORRECT; no optional pairs; allowedActions not used; case-insensitive, trimmed, order-independent";
export const CORRECTNESS_GT_RATIONALE = [
  "v3.0: each expectedActions entry of groundTruthReal.ts is paired with the expectedTargets value whose TargetKind equals the Action Catalog targetKind of that action.",
  "v3.1: TC-04 adds ACT-BLOCK-SOURCE-IP -> @ATTACKER_IP (PB-ACCOUNT-COMPROMISE step 2) and TC-08 adds ACT-BLOCK-HASH -> @KWORKERD_SHA256 (PB-SUSPICIOUS-PROCESS step 2); both are unconditional playbook standard steps whose target is already an expectedTargets value. Verified against playbook.seed.ts before any v3 run; not derived from AI output or from v2/v3 results.",
  "v3.2: TC-02 adds ACT-ISOLATE-ENDPOINT -> attack-endpoint (PB-MALWARE step 1): unconditional playbook standard step, Action Catalog targetKind host, and attack-endpoint (the monitored endpoint / Wazuh agent of the TC-02 simulation) was already an expectedTargets value frozen on 2026-09-30, before any AI output. Same criterion as v3.1; not derived from AI output or from v2/v3 results.",
  "v3.3: TC-05 adds ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test (PB-POWERSHELL step 2). TC-05 uses a controlled REAL_WAZUH PowerShell/DNS scenario. The scenario produced Wazuh rule 100300 (level 12, MITRE T1059.001) from Sysmon Event ID 22 with queryName = vigix-eval-ps-stager.test. The domain was extracted deterministically from data.win.eventdata.queryName, validated as a DOMAIN IOC, re-hunted successfully through WazuhRehuntAdapter, and observed in two independent scenario runs. BLOCK-DOMAIN is therefore the expected action-target pair. ISOLATE-ENDPOINT is excluded because the scenario demonstrates PowerShell/DNS activity but does not provide sufficient evidence that the endpoint was compromised. Approval: IR_TEAM (RULE-P07, severity HIGH). Not derived from AI output, from v2/v3 results or from the mock TC-05 file.",
  "Conditional playbook steps (ISOLATE-ENDPOINT in TC-04, TC-08) are not expected: no scenario evidence that the condition holds.",
];

/** Metadata recorded in every run.json that is scored with this Ground Truth. */
export function correctnessGroundTruthMetadata() {
  return { version: CORRECTNESS_GT_VERSION, source: CORRECTNESS_GT_SOURCE, rule: CORRECTNESS_GT_RULE, rationale: CORRECTNESS_GT_RATIONALE, sha256: correctnessGroundTruthSha256() };
}
