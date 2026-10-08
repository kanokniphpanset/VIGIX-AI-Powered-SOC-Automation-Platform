# Real Wazuh alert fixtures

34 alerts captured **read-only** from the lab Wazuh Indexer (`wazuh-alerts-4.x-*`, Wazuh 4.9.2) on 2026-10-08. They are in the
shape VIGIX receives from the `custom-vigix` integration: the Indexer-added `@timestamp` is removed, nothing else is changed
except masking of the Windows user and host names (`labuser`, `WIN-LAB01`).

| File | Meaning |
|---|---|
| `<ruleId>-<slug>.json` | one alert; rules `100300`-`100350` are **HARNESS_GENERATED** (real Wazuh pipeline, log line written by the evaluation harness), all others **REAL_TELEMETRY** |
| `_index.json` | each alert's Indexer `index` / `_id` (the capture reference) |
| `golden/*.v2.json` | frozen Evidence Contract v2 output of each alert (deterministic: fixed receipt time) |

Rules for these files: they are test inputs only - not evidence that VIGIX "supports" an attack type; mock fixtures
(`resources/mock-attacks-tc`) are compared against them in `test/WazuhEvidenceV2.golden.test.ts`, never substituted for them.

Commands (from `apps/backend`):
```bash
npx jest test/WazuhEvidenceV2.golden.test.ts                    # run
UPDATE_GOLDEN=1 npx jest test/WazuhEvidenceV2.golden.test.ts    # regenerate goldens - review the git diff before committing
npx ts-node --transpile-only scripts/verifyWazuhRealFixtures.ts # re-check fixtures against the live Indexer (read-only GET; needs WAZUH_INDEXER_* env)
```
