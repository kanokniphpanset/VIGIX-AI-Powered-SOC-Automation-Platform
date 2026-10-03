# Scenario Validation Report — evaluation-scenarios-v2

Scope: validation of the 10 evaluation scenarios **before** any fix, freeze or paper claim. No PASS/FAIL is assigned (no evaluation was run for this task). No VIGIX code, prompt, validator, catalog, policy, re-hunt adapter, evaluator, metric or ground truth was changed.
Evidence used: the scenario/ground-truth/simulation sources and the **raw alerts and IOC rows observed in `soar_mockv2_eval`** (Mock v2 run, `results/runs/mock-evaluation-v2-20261002/`) — used only to check that the specified evidence and IOCs actually exist, not to judge the AI. Companion file: `evaluation-scenarios-v2.md`.

## 1. Scenario Validation Matrix
Columns answer: does the specified item exist and is it usable? ✔ yes, ◐ partly, ✘ no.
| Case | Scenario | Alert | Evidence | Ground Truth | IOC | Re-huntable | Verification | Environment | Status |
|---|---|---|---|---|---|---|---|---|---|
| TC-01 Brute Force | ✔ | ✔ stock 5712 | ✔ | ✔ | ✔ IPV4, USERNAME | ✔ IP | ✔ sensitive (control run NOT_RESOLVED) | ✔ | **READY** |
| TC-02 Malware | ✔ | ✔ custom 100301 (syscheck) | ✔ path, sha256, host, time | ✔ | ◐ valid in the alert, **not extracted** into an IOC | ◐ adapter supports `syscheck.sha256_after`; incident has no IOC | ✘ `REHUNT_INSUFFICIENT_CRITERIA` | ✔ | **REHUNT_CAPABILITY_GAP** (+ POTENTIAL SYSTEM ISSUE PSI-1) |
| TC-03 Phishing | ✔ | ✔ custom 100310 | ✔ | ✔ | ✔ URL/DOMAIN/IP/EMAIL (needs analyst promotion to be targetable) | ✔ URL, DOMAIN, IP (EMAIL not searchable) | ✔ | ✔ | **READY** (note PSI-3) |
| TC-04 Account Compromise | ✔ | ✔ stock 40112 | ✔ | ◐ playbook tie-break between T1078/T1110 documented | ✔ IPV4, USERNAME | ✔ IP | ✔ | ✔ | **READY** (note GT-1) |
| TC-05 PowerShell | ✘ not executable | ✘ | ✘ | ✘ rule/IOC not specified (`n/a`) | ✘ | ✘ (anticipated gap: process/command not searchable) | ✘ | ✘ no Windows agent | **ENVIRONMENT_UNAVAILABLE** |
| TC-06 SQL Injection | ✔ | ✔ stock 31103 | ✔ | ✔ | ✔ IPV4 (+HTTP_REQUEST) | ✔ IP | ✔ | ✔ | **READY** |
| TC-07 C2 | ✔ | ✔ custom 100320 | ✔ src/dst roles explicit | ✔ target = `data.dstip` | ✔ DOMAIN, URL, IPV4 ×2 | ✔ | ✔ | ✔ | **READY** |
| TC-08 Suspicious Process | ◐ evidence layout incomplete | ✔ custom 100330 | ◐ no file hash, no parent name; process/command only under `data.audit.*` | ◐ expects QUARANTINE-FILE but the telemetry has no file hash | ✘ no PROCESS/COMMAND IOC extracted automatically | ✘ no searchable field in the alert | ◐ re-hunt could not detect recurrence | ✔ | **NEEDS_FIX** (+ PSI-2, secondary re-hunt gap) |
| TC-09 Data Exfiltration | ✔ | ✔ custom 100340 | ✔ src/dst roles explicit | ✔ target = `data.dstip` | ✔ DOMAIN, URL, IPV4 ×2, FILE_PATH | ✔ | ✔ | ✔ | **READY** |
| TC-10 Privilege Escalation | ◐ label vs ground-truth attack type (see GT-2) | ✔ custom 100350 | ◐ no source user / process / command field | ◐ see GT-2 | ◐ USERNAME only | ✘ USERNAME not searchable | ✘ `INSUFFICIENT_REHUNT_CRITERIA` | ✔ | **REHUNT_CAPABILITY_GAP** |

## 2. Per-case validation report
| Case | Current status | Missing data | Missing evidence | IOC problem | Re-hunt problem | Environment problem | Ground-truth problem | Potential VIGIX problem | Required fix (layer) |
|---|---|---|---|---|---|---|---|---|---|
| TC-01 | READY | — | — | — | — | — | placeholder user = any of 10 attempted users (documented revision) | — | none |
| TC-02 | REHUNT_CAPABILITY_GAP | — (scenario complete: path, name, hash, host, time, alert all present) | — | Hash `275a021b…` and path exist in `syscheck.sha256_after` / `syscheck.path` but the incident has **0 IOCs** (Mock v2 iocRecall 0/2) | Adapter *can* search `syscheck.sha256_after`; with no IOC the re-hunt fails `REHUNT_INSUFFICIENT_CRITERIA`. A host-only response (ISOLATE-ENDPOINT) adds no criterion because the query is IOC-only (hosts and rule are not search clauses) | — | none; the expected IOCs are valid and traceable to the simulation | **PSI-1** (below) | VIGIX (IOC extraction) — not scenario |
| TC-03 | READY | — | — | EMAIL IOC is stored as a stringified object (`{'to': …, 'from': …}`) in addition to the clean sender address; URL/domain/IP/e-mail are "aggregated" and became targetable only after analyst promotion (intervention in the final and Mock v2 runs) | EMAIL not searchable (URL/domain/IP are) | — | ground truth already documents the e-mail-target caveat | **PSI-3** | VIGIX (observation only); none for scenario |
| TC-04 | READY | — | — | — | — | — | **GT-1** alert asserts T1078 and T1110; expected playbook relies on a documented selector tie-break | — | SCENARIO/GT: keep the note in the spec (done in `evaluation-scenarios-v2.md`) |
| TC-05 | ENVIRONMENT_UNAVAILABLE | everything (no telemetry) | everything | none can be defined without calibration | anticipated: process/command line are not re-huntable | no Windows agent; local Windows host has no Wazuh service, no Sysmon, Script Block Logging off | rule id/level/IOC unspecified | — | ENVIRONMENT: provision a Windows endpoint, then calibrate rule + IOCs; otherwise declare as a limitation |
| TC-06 | READY | — | — | URL IOC is a relative request path (not re-huntable); the searchable IOC is the source IP | — | — | — | — | none |
| TC-07 | READY | — | — | — | — | container IPs change after Docker restarts (handled by placeholders) | target role must be read as `data.dstip`; role semantics are now explicit in the spec | role was lost before the LLM (fixed earlier; observation: `results/runs/targetrole-v2-…/ROOT-CAUSE.md`) | none for scenario |
| TC-08 | NEEDS_FIX | file hash; parent-process name | `QUARANTINE-FILE` needs FILE_HASH, absent from the telemetry | No PROCESS/COMMAND IOC is extracted: the extractor reads `data.process`/`data.command` but the telemetry uses `data.audit.exe`/`data.audit.command`; no FILE IOC exists for QUARANTINE-FILE | The only IOCs are text-derived DOMAIN/URL; the alert has no `data.dns`/`data.url` field, so a re-hunt could never match even on recurrence ⇒ a `RESOLVED` would not prove containment | — | **GT-3** preferred actions (`KILL-PROCESS`, `QUARANTINE-FILE`) assume evidence the scenario does not emit | **PSI-2**; the 5 rejected recommendations in Mock v2 (`TARGET_TYPE_MISMATCH` host/process vs process/file, `INSUFFICIENT_EVIDENCE` COMMAND_LINE / FILE_HASH) are *consistent with* these evidence gaps; the cause is not proven | SCENARIO: emit honest attributes the simulation really has (`data.command`; sha256 of the real `/tmp/.cache/kworkerd`; parent process name) in fields the extractor reads; VIGIX: decide separately whether `data.audit.*` must be extracted |
| TC-09 | READY | — | — | — | — | IPs change after Docker restarts (placeholders) | target role = `data.dstip` | same as TC-07 | none for scenario |
| TC-10 | REHUNT_CAPABILITY_GAP | source user, process, command (only in `full_log` text) | privilege-change evidence is limited to `data.dstuser` + `data.vigix_group=sudo` | USERNAME only — valid and traceable, but not a re-huntable type | `INSUFFICIENT_REHUNT_CRITERIA`: no IP/domain/URL/hash exists in a local `usermod` event and none may be invented | — | **GT-2** label "Privilege Escalation" vs ground-truth attack type ACCOUNT_COMPROMISE / PB-ACCOUNT-COMPROMISE (T1098 → this playbook; PB-PRIV-ESC maps T1068/T1548) | — | none for the scenario (no invention); VIGIX/re-hunt: capability question (user/process re-hunt) |

## 3. Potential system issues (reported, **not fixed**)
| ID | POTENTIAL SYSTEM ISSUE | Evidence | Affects |
|---|---|---|---|
| PSI-1 | `extractAlertIocs` reads only `data.*` (+`data.win.eventdata`) — FIM alerts carry hash/path in `syscheck.*` and yield **no IOC**, although `incidentTypeFacts.ts:58-59` already reads `syscheck.path`/`syscheck.sha256_after` as alert facts and the re-hunt adapter searches `syscheck.sha256_after` | `alertIocs.ts:39-76` (no syscheck branch); DB: incident of rule 100301 has 0 IOC rows; Mock v2 `iocRecall {expected 2, found 0}`; verification `REHUNT_INSUFFICIENT_CRITERIA` | TC-02 (and any FIM-based malware case) |
| PSI-2 | The IOC extractor does not read auditd-style `data.audit.exe` / `data.audit.command`; `data.process` cannot be used by the scenario because the Wazuh index maps it as an object | `alertIocs.ts:69,71`; alert payload of rule 100330; Mock v2 intervention "added PROCESS_NAME / COMMAND_LINE IOC" | TC-08 |
| PSI-3 | EMAIL IOC created from `data.email` is a stringified dict; controlled-telemetry IOCs (URL/domain/IP/e-mail) are only "aggregated" and need analyst promotion before they are targetable | `threat_intel_iocs` rows of rule 100310 in `soar_mockv2_eval`; interventions in the final and Mock v2 runs | TC-03 |
| PSI-4 | Re-hunt criteria are IOC-only: `hosts` and `rule` passed by `RunRehuntVerification` are not search clauses; a case whose IOCs are all non-searchable cannot be verified at all | `WazuhRehuntAdapter.ts` `buildQuery` (`No supported IOC is available to query.`); `REHUNT_IOC_TYPES` = IP/DOMAIN/URL/HASH only | TC-02, TC-08, TC-10, TC-05 (anticipated) |
| PSI-5 | Recommendation target role was lost before the LLM (already fixed by `networkRole`; effect: 18/20 destination picks, 0/20 source picks in the diagnostic order experiment; TC-07/09 correct in Mock v2) | `results/runs/targetrole-v2-…/ROOT-CAUSE.md`, Mock v2 `REPORT.md` | TC-07, TC-09 |

## 4. Traceability matrix
`Attack → Alert → Evidence → Investigation → Recommendation → Action → Target → Human decision → Response → Verification → Re-hunt → Final state`. ✔ chain link defined and usable; ✘ break.
| Case | Attack | Alert | Evidence | Investig. | Recomm. | Action | Target | Decision | Response | Verif. | Re-hunt | Final | Chain |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| TC-01 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ srcip | ✔ | ✔ | ✔ | ✔ IP | ✔ | complete |
| TC-02 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ◐ hash/file exist in evidence but not as targetable IOC | ✔ | ✔ | ✘ | ✘ **break: Evidence → IOC (PSI-1)** | open | broken at IOC / re-hunt |
| TC-03 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ◐ needs analyst promotion (PSI-3) | ✔ | ✔ | ✔ | ✔ URL/DOMAIN/IP | ✔ | complete with a known intervention |
| TC-04 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ IP | ✔ | complete |
| TC-05 | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | n/a | broken at **Attack** (environment) |
| TC-06 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ srcip | ✔ | ✔ | ✔ | ✔ IP | ✔ | complete |
| TC-07 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ dstip | ✔ | ✔ | ✔ | ✔ | ✔ | complete |
| TC-08 | ✔ | ✔ | ◐ | ✔ | ◐ | ◐ | ✘ **break: Evidence → target (no PROCESS/FILE IOC, no hash)** | ✘ not reached in Mock v2 | ✘ | ✘ | ✘ no searchable criterion | open | broken at evidence/IOC |
| TC-09 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ dstip | ✔ | ✔ | ✔ | ✔ | ✔ | complete |
| TC-10 | ✔ | ✔ | ◐ | ✔ | ✔ | ✔ | ✔ user | ✔ | ✔ | ✘ | ✘ **break: Re-hunt (USERNAME not searchable)** | open | broken at verification |

## 5. Change Recommendation (one layer per item; nothing applied)
| # | Problem | Layer | Proposed action | Notes |
|---|---|---|---|---|
| 1 | Ground truth lacks machine-readable expected re-hunt criteria, expected verification result, expected final state and target role (they exist only as generic text `expectedVerification`) | **SCENARIO** | Add per-case fields to the ground-truth spec (values in `evaluation-scenarios-v2.md`) *before* the next run and hash them | must not be derived from AI output |
| 2 | TC-08 telemetry omits attributes the real simulation has (command as `data.command`, sha256 of the real binary, parent process name) and expects QUARANTINE-FILE without a hash | **SCENARIO** | Emit those honest attributes in fields the extractor reads; or reduce preferred actions to what the telemetry can support | not a forced target; do not make the agent pick PROCESS |
| 3 | TC-08 `data.audit.*` is ignored by the IOC extractor | **VIGIX** (PSI-2) | Decide whether to extend extraction to the auditd layout | separate decision, after item 2 |
| 4 | TC-02 FIM hash/path not turned into IOCs | **VIGIX** (PSI-1) | Decide whether `syscheck.*` must feed the IOC list | not a scenario change; scenario is already valid |
| 5 | Re-hunt cannot use host/rule/user/process criteria | **VIGIX** (re-hunt capability, PSI-4) | Decide: declare a limitation (TC-10, TC-08 recurrence) or plan a capability extension | no invented IOC meanwhile |
| 6 | TC-03 e-mail IOC stringified / needs promotion | **VIGIX** (PSI-3) | observation; low priority | |
| 7 | TC-05 no Windows telemetry | **ENVIRONMENT** | Provision Windows endpoint (agent 4.9.2, Script Block Logging, Sysmon or equivalent), calibrate the rule, then specify the case; else declare as a limitation | |
| 8 | Container IPs change after Docker restarts; Wazuh API host port moved 55000→55500 (Windows reserves 54950–55049) | **ENVIRONMENT** | record in the run configuration; placeholders already used | |
| 9 | TC-04 ground truth depends on a selector tie-break; TC-10 label vs ground-truth attack type | **SCENARIO** (documentation) | keep GT-1/GT-2 notes in the spec; do not rewrite ground truth to match AI | |
| 10 | Cases with no valid recommendation are "not evaluated" in the compliance denominator | **EVALUATOR** (reporting definition only) | report both denominators (done in Mock v2) before freeze; no formula change proposed here | |

## 6. Limits
- **Environment limits:** TC-05 (no Windows endpoint — verified, see spec); lab IPs are not fixed; Wazuh API reachable only on host port 55500 on this machine; CTI provider (MISP) was unhealthy in the final runs (unchanged here).
- **Re-hunt limits (current `REHUNT_PROVIDER=wazuh`):** only IP, DOMAIN, URL, HASH are searchable, and only if they are present as IOCs of the incident; USERNAME, FILE_PATH, PROCESS_NAME, COMMAND_LINE, EMAIL are not; hosts/rule are not criteria. Direct consequences: TC-10 `INSUFFICIENT_REHUNT_CRITERIA`; TC-08 cannot detect recurrence; TC-02 blocked by PSI-1, not by the adapter.
- **Not claimed:** causes for the TC-08 recommendation failures in Mock v2 are consistent with the evidence gaps above but are **not proven**; no VIGIX behaviour was changed to test that.

## 7. Final Evaluation Readiness Matrix
| Case | Readiness | Primary reason | Secondary flags |
|---|---|---|---|
| TC-01 | **READY** | complete chain, searchable IOC | — |
| TC-02 | **REHUNT_CAPABILITY_GAP** | scenario valid; hash is searchable by the adapter but is not extracted as an IOC | POTENTIAL SYSTEM ISSUE PSI-1 |
| TC-03 | **READY** | complete chain, searchable URL/DOMAIN/IP | known analyst promotion (PSI-3) |
| TC-04 | **READY** | complete chain | GT-1 selector tie-break |
| TC-05 | **ENVIRONMENT_UNAVAILABLE** | no Windows agent / Script Block Logging / Sysmon | spec incomplete until calibrated |
| TC-06 | **READY** | complete chain | — |
| TC-07 | **READY** | complete chain, role explicit | depends on the `networkRole` fix |
| TC-08 | **NEEDS_FIX** | evidence layout incomplete (no hash/`data.command`), no automatic PROCESS/COMMAND/FILE IOC, no searchable re-hunt criterion | PSI-2, PSI-4 |
| TC-09 | **READY** | complete chain, role explicit | depends on the `networkRole` fix |
| TC-10 | **REHUNT_CAPABILITY_GAP** | USERNAME-only IOC → `INSUFFICIENT_REHUNT_CRITERIA` | GT-2 label/attack-type |

Counts: READY 6 (TC-01, TC-03, TC-04, TC-06, TC-07, TC-09), NEEDS_FIX 1 (TC-08), ENVIRONMENT_UNAVAILABLE 1 (TC-05), REHUNT_CAPABILITY_GAP 2 (TC-02, TC-10). Total 10.

## 8. Final decision (per the task's decision rule)
- **NEEDS_FIX (TC-08)** → fix the scenario first (changes #1–#2), then re-validate.
- **ENVIRONMENT_UNAVAILABLE (TC-05)** → decide: prepare a Windows endpoint (#7) or declare the limitation.
- **REHUNT_CAPABILITY_GAP (TC-02, TC-10)** → decide whether these are declared limitations of the current re-hunt capability or planned capability work (#4, #5).
- **POTENTIAL SYSTEM ISSUE (PSI-1…PSI-4)** → analyse VIGIX only after the scenarios are settled.
- **Do not freeze Mock Evaluation v2** until every case has an explained status and the ground-truth spec additions (#1) are made. No Final Evaluation and no metric freezing was performed in this task.
