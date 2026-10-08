# TC-01 ... TC-10 - real-shaped mock alerts (MOCK_FIXTURE)

Ten Wazuh alerts for the same ten evaluation cases as `resources/mock-attacks-tc/`, but built **from real alerts** captured from the lab
Wazuh Indexer (`apps/backend/test/fixtures/wazuh-real/`). Each file is the real alert field for field, with exactly two changes that
mark it as a mock: a fixture-style `id` (`1790000000.91000N`) and the rule group `vigix_custom` appended. Nothing is added or removed,
so these cannot carry a field (GeoLocation, Suricata keys, mail-auth ...) that a real alert in this lab does not have.

| Case | Real alert it is built from |
|---|---|
| TC-01 | 5712 sshd brute force |
| TC-02 | 100301 executable dropped (FIM `syscheck.*` only - no `data.*` copy) |
| TC-03 | 100310 phishing link (harness event) |
| TC-04 | 40112 failures followed by success (Linux sshd) |
| TC-05 | 100300 Sysmon DNS query from PowerShell |
| TC-06 | 31103 SQL injection |
| TC-07 | 100320 C2 beacon (harness event) |
| TC-08 | 100330 suspicious process (harness event) |
| TC-09 | 100340 exfiltration (harness event) |
| TC-10 | 100350 usermod to sudo (harness event) |

Rules of use:
- They are **MOCK_FIXTURE**: never evidence that VIGIX handles real telemetry. `classifyProvenance` reads the `vigix_custom` group.
- The older `resources/mock-attacks-tc/` set is **frozen** (evaluation ground truth and the mock-alert catalog are keyed to it) and is not replaced. New mock tests use this set.
- This set is not registered in the mock-alert catalog (its keys would collide with the frozen TC-01..TC-10).
- Regenerate with `npx ts-node --transpile-only scripts/buildRealShapeMocks.ts` (from `apps/backend`); output is deterministic.
