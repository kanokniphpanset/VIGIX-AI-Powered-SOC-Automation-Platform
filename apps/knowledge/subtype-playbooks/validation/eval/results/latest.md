# Evaluation results (offline, DRAFT Ground Truth)

- generated: 2026-10-08T10:18:31.510Z | knowledge: 2.0.0+394f9a69
- Ground Truth: validation/eval/ground-truth.draft.json (32 cases) status **DRAFT**, IR reviewed: **false**, sha256 27fd950ff3db4c91...
- runtime: GenerateRecommendationUseCase over in-memory repositories (subtype: SUBTYPE mode enforce with the review override; legacy: mode off with FakeRecommendationAgent)
- LLM: none - deterministic; this is NOT an actual-LLM evaluation
- live: none - no live alert, no database, no service touched
- data classes: RECORDED_ALERT x11, SYNTHETIC_FIXTURE x6, RECORDED_ALERT+ANALYST_ASSERTION x2, RECORDED_ALERT+SIMULATED_ROUND2_RECORDS x13

A score is a score against a DRAFT reference authored by the engineering team; it is not an acceptance result and not a production-quality claim.

| system / round | cases | action precision | action recall | target & scope accuracy | response process correctness | prohibited actions | re-hunt correctness (exact) | re-hunt correctness (propose vs hold) |
|---|---|---|---|---|---|---|---|---|
| subtype / first response | 19 | 100.0% (13/13) | 92.9% (13/14) | 92.9% (13/14) | 100.0% (61/61) | 0.0% (0/13) of ready actions; 0/19 cases | n/a (0/0) | n/a (0/0) |
| subtype / after Re-hunt | 13 | 100.0% (3/3) | 100.0% (3/3) | 100.0% (3/3) | 100.0% (26/26) | 0.0% (0/3) of ready actions; 0/13 cases | 100.0% (14/14) | 100.0% (14/14) |
| subtype / ALL | 32 | 100.0% (16/16) | 94.1% (16/17) | 94.1% (16/17) | 100.0% (87/87) | 0.0% (0/16) of ready actions; 0/32 cases | 100.0% (14/14) | 100.0% (14/14) |
| subtype / legacy-comparable subset, first response | 3 | 100.0% (2/2) | 100.0% (2/2) | 100.0% (2/2) | 100.0% (10/10) | 0.0% (0/2) of ready actions; 0/3 cases | n/a (0/0) | n/a (0/0) |
| subtype / legacy-comparable subset, after Re-hunt | 12 | 100.0% (2/2) | 100.0% (2/2) | 100.0% (2/2) | 100.0% (24/24) | 0.0% (0/2) of ready actions; 0/12 cases | 100.0% (12/12) | 100.0% (12/12) |
| legacy stand-in / first response | 3 | 16.7% (2/12) | 100.0% (2/2) | 0.0% (0/2) | N/A (legacy output has no ready / approval / missing sections) | 75.0% (9/12) of ready actions; 3/3 cases | N/A (legacy has no decision classes) | n/a (0/0) |
| legacy stand-in / after Re-hunt | 12 | 4.2% (2/48) | 100.0% (2/2) | 0.0% (0/2) | N/A (legacy output has no ready / approval / missing sections) | 50.0% (24/48) of ready actions; 12/12 cases | N/A (legacy has no decision classes) | 16.7% (2/12) |

Denominators: precision = TP/(TP+FP) over ready ACTION steps; recall = TP/(TP+FN) over expected actions; scope = expected actions whose matched step has every required and no forbidden scope string; process = checks passed / checks defined (including 2 structural checks per case); prohibited = ready actions the reference forbids / all ready actions; re-hunt = (case, target) expectations.

## Per case

| case | system | data | TP/FP/FN | scope | scope failures | prohibited | process failures | re-hunt (expected -> actual) |
|---|---|---|---|---|---|---|---|---|
| GT-R1-01 | subtype | RECORDED_ALERT | 1/0/0 | 1/1 | - | 0 | - | - |
| GT-R1-01 | legacy | RECORDED_ALERT | 1/3/0 | 0/1 | ACT-AUTH-SOURCE-RESTRICT: missing [SSH (22/TCP) | attack-endpoint] | 3 | - | - |
| GT-R1-02 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-02 | legacy | RECORDED_ALERT | 0/4/0 | 0/0 | - | 4 | - | - |
| GT-R1-03 | subtype | RECORDED_ALERT | 1/0/0 | 1/1 | - | 0 | - | - |
| GT-R1-03 | legacy | RECORDED_ALERT | 1/3/0 | 0/1 | ACT-AUTH-SOURCE-RESTRICT: missing [SSH (22/TCP) | attack-endpoint | ตัวระบุ session/connection] | 2 | - | - |
| GT-R1-04 | subtype | SYNTHETIC_FIXTURE | 2/0/0 | 2/2 | - | 0 | - | - |
| GT-R1-05 | subtype | RECORDED_ALERT | 0/0/1 | 0/1 | ACT-AUTH-SOURCE-RESTRICT: not proposed (target 172.19.0.3) | 0 | - | - |
| GT-R1-06 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-07 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-08 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-09 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-10 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-11 | subtype | RECORDED_ALERT+ANALYST_ASSERTION | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-12 | subtype | SYNTHETIC_FIXTURE | 1/0/0 | 1/1 | - | 0 | - | - |
| GT-R1-13 | subtype | SYNTHETIC_FIXTURE | 3/0/0 | 3/3 | - | 0 | - | - |
| GT-R1-14 | subtype | SYNTHETIC_FIXTURE | 3/0/0 | 3/3 | - | 0 | - | - |
| GT-R1-15 | subtype | SYNTHETIC_FIXTURE | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-16 | subtype | SYNTHETIC_FIXTURE | 2/0/0 | 2/2 | - | 0 | - | - |
| GT-R1-17 | subtype | RECORDED_ALERT+ANALYST_ASSERTION | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-18 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R1-19 | subtype | RECORDED_ALERT | 0/0/0 | 0/0 | - | 0 | - | - |
| GT-R2-01 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: NO_NEW_ACTION -> NO_NEW_ACTION |
| GT-R2-01 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: NO_NEW_ACTION -> PROPOSE |
| GT-R2-02 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: INVESTIGATE -> INVESTIGATE |
| GT-R2-02 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: INVESTIGATE -> PROPOSE |
| GT-R2-03 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: INVESTIGATE -> INVESTIGATE |
| GT-R2-03 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: INVESTIGATE -> PROPOSE |
| GT-R2-04 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: INVESTIGATE -> INVESTIGATE |
| GT-R2-04 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: INVESTIGATE -> PROPOSE |
| GT-R2-05 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: INVESTIGATE -> INVESTIGATE |
| GT-R2-05 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: INVESTIGATE -> PROPOSE |
| GT-R2-06 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: INVESTIGATE -> INVESTIGATE |
| GT-R2-06 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: INVESTIGATE -> PROPOSE |
| GT-R2-07 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: INVESTIGATE -> INVESTIGATE |
| GT-R2-07 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: INVESTIGATE -> PROPOSE |
| GT-R2-08 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: ADJUST -> ADJUST |
| GT-R2-08 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: ADJUST -> PROPOSE |
| GT-R2-09 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 1/0/0 | 1/1 | - | 0 | - | 172.19.0.3: REPEAT -> REPEAT |
| GT-R2-09 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 1/3/0 | 0/1 | ACT-AUTH-SOURCE-RESTRICT: missing [SSH (22/TCP)] | 2 | - | 172.19.0.3: REPEAT -> PROPOSE |
| GT-R2-10 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 1/0/0 | 1/1 | - | 0 | - | 172.19.0.3: REPEAT -> REPEAT |
| GT-R2-10 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 1/3/0 | 0/1 | ACT-AUTH-SOURCE-RESTRICT: missing [SSH (22/TCP)] | 2 | - | 172.19.0.3: REPEAT -> PROPOSE |
| GT-R2-11 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: NO_NEW_ACTION -> NO_NEW_ACTION |
| GT-R2-11 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: NO_NEW_ACTION -> PROPOSE |
| GT-R2-12 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 1/0/0 | 1/1 | - | 0 | - | 172.19.0.3: NO_NEW_ACTION -> NO_NEW_ACTION; 172.19.0.9: ADD -> ADD |
| GT-R2-13 | subtype | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/0/0 | 0/0 | - | 0 | - | 172.19.0.3: NO_NEW_ACTION -> NO_NEW_ACTION |
| GT-R2-13 | legacy | RECORDED_ALERT+SIMULATED_ROUND2_RECORDS | 0/4/0 | 0/0 | - | 2 | - | 172.19.0.3: NO_NEW_ACTION -> PROPOSE |

## Ground Truth titles

- GT-R1-01: sshd brute force from one source; enforcement point known; tools not named
- GT-R1-02: sshd brute force; organization has not named an enforcement point (the repository's real organization context)
- GT-R1-03: sshd brute force; enforcement point AND connection-termination tool confirmed
- GT-R1-04: sshd brute force from two different sources
- GT-R1-05: recorded 40112: several failures followed by a success; enforcement point known
- GT-R1-06: recorded 5503: a single PAM login failure
- GT-R1-07: recorded 100320: outbound connection only
- GT-R1-08: recorded 31103: web request containing SQL keywords
- GT-R1-09: recorded 92027: encoded PowerShell command
- GT-R1-10: recorded 100330: process executed from a world-writable path, no analyst confirmation
- GT-R1-11: recorded 100330 + analyst-confirmed execution chain, process known only by PID
- GT-R1-12: Scheduled Task Hijack: task + payload process (GUID) evidenced; no C2, no file identity
- GT-R1-13: Scheduled Task Hijack with C2 channel + file identity; connection-termination tool confirmed
- GT-R1-14: Scheduled Task Hijack with C2 + file identity; connection-termination tool NOT confirmed
- GT-R1-15: Scheduled Task change that is an AUTHORIZED / approved change
- GT-R1-16: two subtypes in one incident: sshd brute force + Scheduled Task Hijack
- GT-R1-17: unauthorized password authentication confirmed on a CRITICAL asset
- GT-R1-18: IR execution authority explicitly denied in the organization context
- GT-R1-19: required control capability explicitly NOT supported
- GT-R2-01: executed; covered re-hunt newer than execution and evidence found no recurrence
- GT-R2-02: executed; no re-hunt for this cycle
- GT-R2-03: executed; the only re-hunt is older than the execution
- GT-R2-04: executed; re-hunt coverage incomplete (agent offline / stale telemetry)
- GT-R2-05: executed; the target has evidence newer than the re-hunt
- GT-R2-06: re-hunt reports activity in scope, but this target's own evidence is older than the execution
- GT-R2-07: corroborated recurrence; the IR left no record of the control state
- GT-R2-08: corroborated recurrence although the IR attested the control was applied
- GT-R2-09: corroborated recurrence; the IR recorded the control as only PARTIALLY applied
- GT-R2-10: the earlier execution FAILED
- GT-R2-11: the earlier Response Ticket is still open
- GT-R2-12: a second attacker address appears while the first measure is still effective
- GT-R2-13: activity returns on a DIFFERENT host
