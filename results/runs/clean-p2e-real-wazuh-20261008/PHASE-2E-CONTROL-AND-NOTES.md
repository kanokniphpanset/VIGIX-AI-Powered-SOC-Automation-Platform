# Phase 2E - recurrence control, comparability notes and incidents of the run

Companion to `PHASE-2E-REPORT.md` (generated) in this folder. Runs: `clean-p2e-real-wazuh-20261008` (9 cases, DB `soar_p2e_eval`) and
`control-recurrence-p2e-real-wazuh-20261008` (3 cases with the attack repeated after the response, DB `soar_p2e_ctrl_eval`). Both: REAL Wazuh
(agent -> manager -> rules -> Indexer), Evidence Contract v2 on (`EVIDENCE_CONTRACT_V2=true`, this process only), correlating re-hunt (Phase 2D), LLM
recommendation agent. TC-05 was not run (Windows agent offline when the run was planned; chosen by the owner). Code state: HEAD `b03465e` plus the
uncommitted working tree (211 changed paths at launch; another session was editing `src/domain/subtype/` during the run - `--transpile-only`, not imported by this path).

## 1. Recurrence control (does the new semantics still catch a real recurrence?)
The attack is repeated after the response completes; a correct re-hunt must NOT say RESOLVED.

| Case | Provenance | Verification | Re-hunt class | Activity / total matched | Ignored | Reasons | Coverage |
|---|---|---|---|---|---|---|---|
| TC-01 Brute force | REAL_TELEMETRY | **NOT_RESOLVED** (REAL_WAZUH) | IN_SCOPE_ACTIVITY | 29 / 29 | 0 | SAME_RULE 1, SHARED_RULE_GROUP 20 | complete |
| TC-02 Malware (FIM) | HARNESS_GENERATED | **NOT_RESOLVED** | IN_SCOPE_ACTIVITY | 1 / 2 | **1 (the file deletion)** | SAME_RULE, SAME_FILE_PATH, SHARED_RULE_GROUP | complete |
| TC-07 C2 | HARNESS_GENERATED | **NOT_RESOLVED** | IN_SCOPE_ACTIVITY | 3 / 3 | 0 | SAME_RULE 3, SHARED_RULE_GROUP 3 | complete |

- TC-01 matches the frozen control run `control-recurrence-real-wazuh-20260930` (29 matching events, NOT_RESOLVED).
- TC-02 is the live proof of "file deleted != recurrence": of the 2 documents matching the file hash, the deletion was ignored and the re-dropped file counted. Before Phase 2C/2D this case could not be verified at all (no hash IOC was extracted).
- No false RESOLVED in any control case. Each NOT_RESOLVED reopened the investigation (round 2); the round-2 recommendation is outside this control's purpose (TC-01: `NO_NEW_RECOMMENDATION`, a pre-existing guard).
- Harness artifact: for TC-02 the runner's case line reads "NON_COMPLIANT / verification=null" because it scores the latest recommendation after the reopen; the verification itself is in the database (table above) and is NOT_RESOLVED.

## 2. Clean run vs frozen baselines - what is and is not comparable
- **Ground truth differs**: this run is scored against `9a800baba905...`; the baselines `final-main-real-wazuh-20261001` and `clean-v2-real-wazuh-20260930` against `ddb18d5d4dee...`. The ground truth file changed after those runs (for example TC-08 now expects 4 IOCs where the baselines expected 2). IOC recall of TC-08 is therefore **not** like-for-like and no improvement is claimed for it.
- **Like-for-like and attributable to this work**: TC-02 expected 2 IOCs in both; baselines found 0/2 (hash and file path sit in `syscheck.*`, which the old extractor never read) and the re-hunt then failed with `INSUFFICIENT_CRITERIA`; this run found 2/2 and completed a real re-hunt (RESOLVED). TC-01, 03, 04, 06, 07, 09: same recall as baselines, same verdicts.
- **Unchanged limitation**: TC-10 (privilege change) still cannot be re-hunted - its only IOC is a user name, which the IOC-field search does not support (`REHUNT_INSUFFICIENT_CRITERIA`, identical in every baseline).
- **Provenance split** (never pool): REAL_TELEMETRY = TC-01, TC-04, TC-06 (stock rules on real agent logs): 3/3 compliant, 5/5 IOC, 3/3 RESOLVED. HARNESS_GENERATED = TC-02, 03, 07, 08, 09, 10 (rules 100301-100350, log lines written by the harness): 6/6 compliant, 17/17 IOC, 5/6 RESOLVED (TC-10 not verifiable). The harness cases say nothing about independent real telemetry.
- All 8 completed re-hunts in the clean run are `NO_MATCH_COVERED` with complete coverage; that means "no alert-producing event in the searched scope and period" (archives are off), not "no event".
- IOC roles (Phase 2C) recorded for every case in `PHASE-2E-REPORT.md`; the reporting host's own address is `ENDPOINT_SELF` in TC-07/TC-09 (srcip = agent address) and none of the recommended targets was an `ENDPOINT_SELF` value.

## 3. Incidents of this run (disclosed, all resolved before the final runs)
1. **Attempt 1** (`run2e-attempt1`): TC-01/TC-02 failed in under a minute with `NO_VALID_RECOMMENDATION`. Cause: `scripts/eval/wiring.ts` passed `undefined` for the generation playbook catalog reader (Phase 1D), so generation stopped at `PLAYBOOK_PROVENANCE_NOT_FOUND` before any model call. Fixed to mirror `container.ts`; confirmed on a throw-away database copy. Also explains why `clean-p1c-real-wazuh-20261007` stopped at preflight.
2. **Attempt 2**: re-hunt returned INCOMPLETE for every case. Cause: the Phase 2D agent-coverage check counted non-active status snapshots up to 2 hours before the window, although the agent had only reconnected 23 minutes earlier. Fixed: only snapshots inside the window plus the latest one before it count. Three unit tests added; verified against the live Indexer.
3. **Attempt 3**: TC-02 re-hunt INCOMPLETE. Cause: `RunRehuntVerification` adds a response target that is not an IP/hash/URL to `hosts`; with Phase 2D that target (a file path) was checked as an agent. Fixed: only the alert's own agents are required for coverage (`scopeAgents`); three unit tests added.
4. Logs of attempts 1-3 are kept (scratch folder, not in the repo). Each attempt used a freshly reset evaluation database (knowledge base intact).
5. Infrastructure events in the clean run: 6 x `AI_UNAVAILABLE` (TC-02 x3, TC-07, TC-08, TC-09), all recovered after the harness wait; none counted as a model attempt. Model output was sometimes malformed JSON (counted as attempts per the existing rules).
6. `soar_platform` was not touched (272 alerts, newest 2026-10-08 04:21, before and after); the backend on :4000 was stopped by the owner for the whole run.
