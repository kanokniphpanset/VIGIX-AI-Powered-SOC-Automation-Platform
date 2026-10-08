# FREEZE AUDIT — Final Evaluation v3.3 (pre-run)

Recorded 2026-10-03 (before TC-01). Status of this document: **PRE-RUN**. No test case has been executed. A post-run section is appended after the run.

## 1. Ground Truth

| Item | Value |
|---|---|
| Correctness GT version | `correctness-gt-v3.3` |
| GT commit | `444fed9` (`groundTruthCorrectness.ts`, `groundTruthReal.ts`, `correctRecommendation.ts`, `EvaluationService.ts` have **no diff** between `444fed9` and HEAD) |
| Correctness GT SHA-256 (canonical, `correctnessGroundTruthMetadata()`) | `d2f1dae6d576d8e0534bc8a26cae4a7afc5f6a529e06da2f675a5b44855951a8` |
| `REAL_GROUND_TRUTH` SHA-256 (hashed into run.json by the harness) | `9a800baba905dfc8aca73810ef9f4984ac5923b3909eb013984bd11fcc69f6de` |
| `groundTruthCorrectness.ts` file SHA-256 | `36a489881475a3b72b425666efcffe020f7cf700b1eed84c32cedf6dd83f3eb3` |
| `groundTruthReal.ts` file SHA-256 | `89d24951a9a8f2e743cc2c5c070ede1f2a322d4a78d80d9cbaf4b59880e4f3a6` |
| Number of test cases | 10 (TC-01, TC-02, TC-03, TC-04, TC-05, TC-06, TC-07, TC-08, TC-09, TC-10 all present) |
| TC-05 expected recommendation | `ACT-BLOCK-DOMAIN` |
| TC-05 expected target | `vigix-eval-ps-stager.test` |
| TC-05 optional pair | none (`optional: false`, one pair only) |
| TC-05 `ACT-ISOLATE-ENDPOINT` | **not present** |

Expected pairs per case (unchanged from the GT tested in `results/gt-v3.3-test/`): TC-01 1, TC-02 3, TC-03 3, TC-04 3, TC-05 1, TC-06 1, TC-07 2, TC-08 3, TC-09 2, TC-10 1.

## 2. Source and tests

| Item | Value |
|---|---|
| Branch / source commit | `feature/report-period-windows` / `245b5366b1c08034539874193cc50d42cedfcbfb` |
| Tracked source changes vs HEAD (`apps`, `infra`) | none (`git diff --stat HEAD -- apps infra` empty) |
| Untracked files present | `.env.txt`, `apps/backend/scripts/eval/final/rescore-correct-recommendation.ts` (read-only retrospective rescoring script, not used by the run), `results/gt-v3.3-test/`, `results/runs/final-evaluation-v3.3/`, `results/runs/targetrole-v2-tc07-tc09-20261002/soar_v2_eval-before-role-fix.sql` |
| Related test suites | 12 suites, **210 tests passed, 0 failed, 0 skipped** (`metrics/prerun-jest-results.json`, console `logs/prerun-jest-console.txt`); identical to the expected baseline |
| File hashes of evaluation-relevant sources | `metrics/prerun-file-sha256.txt` |

## 3. Evaluation configuration

| Item | Value |
|---|---|
| Evaluation type / mode | REAL_WAZUH / `intervention` (IR decision scripted `approve`) |
| Cases | TC-01 → TC-10, one run |
| Evaluation database | `soar_v33_eval` — created from `soar_tc05_eval` by dump/restore, then all workflow tables truncated |
| DB state before run | alerts 0, incidents 0, recommendations 0, audit_logs 0, approvals 0, evidence 0, verifications 0, response_plans 0 (every other non-empty table is Knowledge Base/config: actions 14, mitre_techniques 26, playbooks 11, playbook_steps 36, policies 29, policy_rules 29, runbooks 17, tenants 1, users 3, notification_recipients 2, migrations) |
| Model | `vllm-spark-01/gemma4-26b-uncensored` (`LLM_PROVIDER` is defined twice in `apps/ai-orchestrator/.env`: `openai-compatible`, then `openrouter`; the effective path is `LLM_BASE_URL` + `LLM_MODEL`; endpoint `/models` HTTP 200) |
| AI orchestrator | uvicorn `src.main:app`, `127.0.0.1:8001`, PID 22152, `/health` ok |
| Process-level overrides (no file edited) | `EVAL_DB=soar_v33_eval`, `WAZUH_API_URL=https://localhost:55500`, `TC05_OPERATOR_WAIT_MS=1800000`, plus `eval-env.sh` (`RECOMMENDATION_AGENT=llm`, `REHUNT_PROVIDER=wazuh`) |
| Backend | the harness invokes the application use cases in-process (`wiring.ts`: `IngestAlertFromSiemUseCase` etc.); the backend HTTP server is **not running** and no HTTP webhook is exercised in this evaluation (same as all previous REAL_WAZUH runs) |

## 4. Runtime database verification (orchestrator :8001)

`/health` was **not** used as evidence. Evidence:
1. The launcher `start-orchestrator-v33.ps1` sets `EVAL_DB=soar_v33_eval` and calls the repository's `scripts/eval/eval-env.sh start-orchestrator`, which exports `DATABASE_URL` = `.../soar_v33_eval` (verified: the harness process resolves `DATABASE_URL` to `.../soar_v33_eval`).
2. PostgreSQL `pg_stat_activity`: exactly 5 connections to `soar_%` databases, **all to `soar_v33_eval`** (backend start 11:28:26 UTC); zero connections to `soar_tc05_eval` or `soar_platform`.
3. Windows `Get-NetTCPConnection -OwningProcess 22152` shows exactly 5 established connections to `:5432` (local ports 61728–61732), and `netstat -ano` shows the matching 5 server-side sockets on `:5432` (owned by PID 10484, the process publishing the Postgres port; not separately identified) — the number of PID-22152 connections equals the number of `soar_v33_eval` sessions, and no other client holds a session.
4. The old orchestrator (bound to `soar_tc05_eval`) is no longer running (0 connections to that database).

Conclusion: the runtime of the process listening on `:8001` is bound to `soar_v33_eval`. (Limit: the port-to-session pairing is by connection count and timing; the repository has no endpoint that reports the active DB and none was added.)

## 5. Preflight (harness checks, `logs/preflight-dry.txt`, run with `--cases NONE`: infrastructure checks only, no case executed)

PASS: evaluation database `soar_v33_eval`; `REHUNT_PROVIDER=wazuh`; `RECOMMENDATION_AGENT=llm`; AI orchestrator health; Wazuh Indexer + re-hunt adapter (cluster green, 5 indices, `wazuh-alerts-4.x-*`); Wazuh manager API UP (analysisd, remoted, logcollector, integratord; 3 active agents); agent attack-endpoint Active; custom rules 100310/100320/100330/100340/100350 loaded (wazuh-logtest); Knowledge Base complete for ground-truth references (11 playbooks, 26 MITRE, 14 actions).

Supplementary checks performed outside the harness:

| Check | Result |
|---|---|
| PostgreSQL | `soar-postgres` healthy; `soar_v33_eval` reachable |
| Qdrant | `soar-qdrant` :6333 `/collections` HTTP 200 (backend config `QDRANT_URL=http://localhost:6333`); `vigix-eval-qdrant` :6335 also up |
| LLM endpoint | `/models` HTTP 200 |
| Wazuh manager | `single-node-wazuh.manager-1` up; manager API reachable at host port 55500 |
| Windows agent 010 | `vigix-win10-ps`, Windows 10 Education, Wazuh v4.9.2, **Active** (last keep-alive 21 s before the check) |
| Rule 100300 | manager copy of `vigix_eval_rules.xml` SHA-256 `f3da602b…0f9a` = repository copy; level 12, MITRE T1059.001, `if_sid 61650`, image `powershell.exe`, `queryName` = `vigix-eval-ps-stager.test` |
| Sysmon / telemetry history | indexer holds 3 earlier genuine rule-100300 alerts from agent `vigix-win10-ps` (Sysmon eventID 22, level 12, T1059.001, queryName `vigix-eval-ps-stager.test`) at 09:59:32, 10:06:38 and 10:38:01 UTC — evidence that Sysmon event 22 → rule 100300 → indexer works |
| Live Sysmon status on the VM | **NOT directly verified in this audit** (the VM is not reachable from this session); indirectly supported by the active agent and the alerts above. Live proof of the full chain for this run is produced when the operator triggers TC-05 |
| TC-05 KB in `soar_v33_eval` | `PB-POWERSHELL` (4 steps), `T1059.001`, `ACT-BLOCK-DOMAIN` enabled, `ACT-ISOLATE-ENDPOINT` enabled (the catalog is unchanged; ISOLATE is simply not in the GT) |
| Re-hunt control | unrelated domain `vigix-eval-control-unrelated.test` → 0 matches in `wazuh-alerts-4.x-*` |
| IOC extraction | covered by `RealWazuhSysmonDnsIoc.test.ts` (7 tests, pass); `alertIocs.ts` extracts `data.win.eventdata.queryName` as DOMAIN |

Note: the harness preflight for TC-05 (agent 010 Active + rule 100300 hash) and for the full Knowledge-Base check runs again at the start of the real run with all 10 cases; a failure there exits before TC-01 with code 3.

## 6. Open items before the run

* TC-05 requires an operator action on the Windows VM at its turn (`[System.Net.Dns]::GetHostAddresses('vigix-eval-ps-stager.test')` in PowerShell); wait limit 30 minutes. Timing mode will be recorded as OPERATOR_TRIGGERED.
* Earlier rule-100300 alerts for the same domain exist in the indexer; the re-hunt is time-window bounded (as in the previous TC-05 run).
* The run is not started by this document.

## 7. Post-run integrity (appended after the run)
* Run `final-evaluation-v3.3`: 2026-10-03T11:38:02Z to 12:04:53Z, exit 0, `run.json` written, 10 cases, 0 infrastructure events.
* Correctness GT SHA-256 after the run `d2f1dae6d576d8e0534bc8a26cae4a7afc5f6a529e06da2f675a5b44855951a8` and `REAL_GROUND_TRUTH` `9a800bab...69f6de`: unchanged.
* All files listed in `metrics/prerun-file-sha256.txt`: unchanged (sha256sum -c, no mismatch). HEAD `245b536`; no tracked change.
* Evaluation DB `soar_v33_eval`: 10 alerts, 10 incidents, 9 recommendations, 7 verifications, 9 response plans (matches the run).
* Nothing was committed.
