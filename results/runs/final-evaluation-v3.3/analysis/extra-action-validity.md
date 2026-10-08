# Extra Recommendation Validity Analysis — Final Evaluation v3.3

Post-hoc, read-only analysis. Frozen inputs: run `final-evaluation-v3.3` (`run.json`, `cases/TC-*.json`), `correctness-gt-v3.3` (SHA-256 `d2f1dae6…5951a8`, commit `444fed9`), source `245b536`, model `vllm-spark-01/gemma4-26b-uncensored`, DB `soar_v33_eval`. Evidence was taken only from this run (`evidence-extract.json`, a read-only extract of the frozen DB: alerts, evidence, IOCs, recommendation steps). Playbooks, action catalog and policies are the frozen seeds (`playbook.seed.ts`, `actionKnowledge.ts`, `policy.seed.ts`). No LLM was called and no model self-judgement is used.

## 1. Primary result (unchanged)

```text
Correct Recommendation: 4/10 = 40.00%
```

Under the strict exact action-target matching criterion, 4 of 10 cases matched the frozen Ground Truth. This analysis does not recalculate or adjust that figure and defines no adjusted accuracy.

## 2. Per-case separation

| Case | Exact GT Match | Required Action Coverage | AI pairs | Unexpected | Extra Action Validity |
|---|---|---|---|---|---|
| TC-01 | PASS | 1/1 | 1 | 0 | — |
| TC-02 | FAIL | **1/3** (missing QUARANTINE-FILE, BLOCK-HASH) | 1 | 0 | — (no extra; the failure is missing required actions) |
| TC-03 | PASS | 3/3 | 3 | 0 | — |
| TC-04 | FAIL | 3/3 | 4 | 1 | REVOKE-SESSION → VALID |
| TC-05 | FAIL | 0/1 (no recommendation produced) | 0 | 0 | — |
| TC-06 | PASS | 1/1 | 1 | 0 | — |
| TC-07 | FAIL | 2/2 | 4 | 2 | BLOCK-URL → VALID; ISOLATE-ENDPOINT → VALID |
| TC-08 | PASS | 3/3 | 3 | 0 | — |
| TC-09 | FAIL | 2/2 | 4 | 2 | BLOCK-URL → VALID; ISOLATE-ENDPOINT → PARTIALLY_SUPPORTED |
| TC-10 | FAIL | 1/1 | 2 | 1 | REVOKE-SESSION → PARTIALLY_SUPPORTED |

## 3. Extra action matrix (6 extra pairs; targets are the actual AI targets read from `cases/TC-*.json`)

| TC | Extra Action | Target (actual) | Evidence | Playbook | Policy | Target Validity | Overall |
|---|---|---|---|---|---|---|---|
| TC-04 | ACT-REVOKE-SESSION | victim | SUPPORTED | ALIGNED | COMPLIANT_WITH_APPROVAL | CORRECT | **VALID_EXTRA_ACTION** |
| TC-07 | ACT-BLOCK-URL | http://vigix-eval-c2.net:8080/gate.php | SUPPORTED | ALIGNED | COMPLIANT_WITH_APPROVAL | CORRECT | **VALID_EXTRA_ACTION** |
| TC-07 | ACT-ISOLATE-ENDPOINT | attack-endpoint | SUPPORTED | ALIGNED | COMPLIANT_WITH_APPROVAL | CORRECT | **VALID_EXTRA_ACTION** |
| TC-09 | ACT-BLOCK-URL | http://vigix-eval-exfil.net:8080/upload | SUPPORTED | ALIGNED | COMPLIANT_WITH_APPROVAL | CORRECT | **VALID_EXTRA_ACTION** |
| TC-09 | ACT-ISOLATE-ENDPOINT | attack-endpoint | PARTIALLY_SUPPORTED | ALIGNED | COMPLIANT_WITH_APPROVAL | CORRECT | **PARTIALLY_SUPPORTED** |
| TC-10 | ACT-REVOKE-SESSION | evaluser | INSUFFICIENT_EVIDENCE (session aspect) | CONDITIONALLY_ALIGNED (condition not satisfied) | COMPLIANT_WITH_APPROVAL | CORRECT | **PARTIALLY_SUPPORTED** |

## 4. Reasoning per pair

**TC-04 — REVOKE-SESSION → victim.** Evidence: Wazuh rule 40112 (level 12), sshd "Accepted password for victim from 172.19.0.3" after repeated failures — a successful authenticated session of the account; the USERNAME and IPV4 IOCs are ACTIVE. Playbook: PB-ACCOUNT-COMPROMISE allows it and step 4 (unconditional) pairs "reset the credentials *and revoke the active sessions* of the account recorded in the authentication evidence". Policy: impact MEDIUM; IR_TEAM approval required under RULE-P07 (the recommendation does not execute). Target: account IOC from the alert. Note: the GT includes ACT-RESET-CREDENTIAL (the same playbook step) but not ACT-REVOKE-SESSION.

**TC-07 — BLOCK-URL.** The URL is a verbatim field of the alert (`data.url`, HTTP 200 beacon) and an ACTIVE URL IOC; PB-C2 step 1 lists IP/domain/URL; POL-A02 requirements met. It is redundant with the expected domain block, not contradictory.

**TC-07 — ISOLATE-ENDPOINT → attack-endpoint.** Regular 2-second beaconing from 172.19.0.8 (agent attack-endpoint) to the C2 destination (rule 100320, level 13) is itself an indicator of endpoint compromise, which is the catalog's analyst condition for this action; PB-C2 step 2 is unconditional ("isolate the endpoint that communicated with the C2 destination"); POL-A01 requires IR_TEAM approval. Caveat: the alert records beacon 1 of 3.

**TC-09 — BLOCK-URL.** The upload URL is in the alert (`data.url`) and is an ACTIVE URL IOC; PB-DATA-EXFIL step 1 lists URL. No threat-intelligence verdict exists for the destination (reputation empty), so the justification rests on the alert event alone.

**TC-09 — ISOLATE-ENDPOINT → attack-endpoint (PARTIALLY_SUPPORTED).** The alert proves a 3 MB upload from the endpoint but describes it as "possible data exfiltration"; no process, hash or intel indicator shows the endpoint is compromised. Playbook step 2 is unconditional and the target/policy are valid, but the evidence for the catalog condition "evidence supports compromise of the endpoint" is only partial — the same principle the GT applies to TC-05 (activity alone does not establish compromise).

**TC-10 — REVOKE-SESSION → evaluser (PARTIALLY_SUPPORTED).** The only evidence is a `usermod` log adding `evaluser` to `sudo` (rule 100350, level 14, critical). There is no login, session or authentication event, so an active or suspicious session is not evidenced and a username alone is not sufficient for session revocation. The account is genuinely implicated and the target kind/value are correct. The playbook step applies the action to "the account recorded in the authentication evidence", which does not exist in this case (condition not satisfied). Observation: the validator accepted the step because its AUTHENTICATION_EVIDENCE check passes whenever any evidence row names the account.

## 5. Descriptive metrics (do not replace the primary metric)

| Metric | Value |
|---|---|
| Required Action Coverage | 17/20 required pairs = **85.00 %** (TC-02 covered 1/3; TC-05 0/1) |
| Unexpected Action Rate | 6/23 AI pairs = **26.09 %** |
| Extra Action Validity Rate | 4/6 = **66.67 %** (denominator = 6 extra pairs with determinate validity; 0 INDETERMINATE; the 2 PARTIALLY_SUPPORTED pairs are in the denominator and not counted as valid) |

## 6. Final summary

**Primary result.** Correct Recommendation 4/10 = 40.00 %, unchanged.

**Extra action analysis (6 extra pairs).** Evidence: 4 supported, 1 partially supported, 1 insufficient (session aspect). Playbook: 5 aligned, 1 conditionally aligned with the condition not satisfied. Policy: 6 compliant with IR_TEAM approval, 0 non-compliant. Target: 6 correct. Overall: **4 valid, 2 partially supported, 0 unsupported, 0 policy-invalid, 0 target-invalid, 0 indeterminate.**

**Interpretation.**
* TC-02 failed because required actions are *missing* (coverage 1/3) — that is a coverage failure, not an extra-action question.
* TC-04, TC-07, TC-09 and TC-10 contain *all* required pairs (coverage 100 %) and fail the strict metric only through unexpected actions.
* An action that is not in the GT is neither automatically wrong nor automatically right. Here four of the six extras are supported by case evidence, an unconditional playbook step, policy (with IR approval) and an evidence-linked target; two are only partially supported.
* Observation about the GT (no change made): the playbook steps behind the extras (PB-C2 steps 1-2, PB-DATA-EXFIL steps 1-2, PB-ACCOUNT-COMPROMISE step 4) are unconditional in the seed text, while the GT derivation rule added unconditional steps only for TC-02, TC-04 (step 2) and TC-08. This is a statement about GT coverage, not a correction of it.
* These findings are post-hoc, rest on a single run, and the 2 partial judgements involve reasoning about whether the evidence shows endpoint compromise or an active session; they could be judged differently by another reviewer.

## 7. Research integrity statement

This analysis was performed after the completion of Final Evaluation v3.3 and did not modify the frozen Ground Truth, evaluation logic, source code, case artifacts, or primary evaluation result. Additional recommendations were assessed independently against the evidence, playbook, policy, and target requirements available in the frozen evaluation artifacts.

Integrity record: SHA-256 of `run.json`, of each `cases/TC-*.json` and of `evidence-extract.json` are stored in `extra-action-validity.json` (`integrity`); `run.json` was verified unchanged by the analysis script (`sha256sum -c`).
