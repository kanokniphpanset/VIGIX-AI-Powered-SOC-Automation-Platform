# TC-07 / TC-09 — BLOCK-DESTINATION-IP aimed at the source IP (root-cause trace, read-only)

Status: PRE-FIX result (7/9 = 77.78% with the `targetRole` criterion). Not a final evaluation result.
Environment: DB `soar_v2_eval`; run with `WAZUH_API_URL=https://localhost:55500` (host port moved from 55000, which Windows reserves — environment fix, not VIGIX logic).

## Trace
| Stage | Role of the IPs known? | Evidence |
|---|---|---|
| Wazuh alert | YES | `data.srcip=172.19.0.6` (endpoint), `data.dstip=172.19.0.5` (server) |
| `extractAlertIocs` (`domain/investigation/alertIocs.ts`) | YES, in `path` (`data.srcip` / `data.dstip`) | returned per IOC |
| `threat_intel_iocs` row | **NO** | `ioc_type=IPV4`, `source=ALERT`, no role/path/added_reason |
| `RecommendationContextIoc` (what the LLM sees) | **NO** | fields: iocType, iocValue, source, reputationScore, manual, ref — no role |
| Action catalog `ACT-BLOCK-DESTINATION-IP` | role-blind | `targetKind: "ip"` only; `checkRequirement` matches by kind |
| Validator / evidenceSupport | role-blind | any evidence-linked IPV4 passes |
| LLM pick | position-driven | picked `.6` (listed first) for both cases |

## Corroboration
`results/extended-evaluation/extended-rag.json` `ipOrderDiagnostic`: same incident, IPs reversed in the input —
destination picks correct 4/5 and 5/5 as built, **0/5 and 0/5** reversed. The choice follows list order, not role.

## Conclusion (hypothesis supported, not yet fixed)
The role is lost when the alert IOC is persisted/serialised into the recommendation context. The LLM cannot tell source
from destination, and neither the validator nor the old evaluator checks it. The earlier "correct" results were order luck.
Candidate fixes (not applied): carry role into the IOC / context (`srcip`/`dstip` label), and make the validator enforce
role for BLOCK-SOURCE-IP / BLOCK-DESTINATION-IP.

## Follow-up: role added to IOC context (only change; validator/catalog/evaluator/test cases untouched)
Run `results/runs/targetrole-v3-rolectx-tc07-tc09-20261002/`: TC-07 and TC-09 both COMPLIANT, BLOCK-DESTINATION-IP -> 172.19.0.5
(the alert's dstip), retries 0, verification RESOLVED (REAL_WAZUH). Sample size: one generation per case — not yet repeated or order-reversed.
Pre-fix DB dump kept as `soar_v2_eval-before-role-fix.sql`.

## Order experiment with role context (5 reps x 2 orders x TC-07/TC-09; real LLM, real validator, nothing persisted)
Data/log: `results/runs/targetrole-v3-rolectx-tc07-tc09-20261002/order-experiment-rolectx.json` / `.log`.
| Case | as_built (.6 first) | ips_reversed (.5 first) |
|---|---|---|
| TC-07 | 5/5 destination | 4/5 destination, 1 no destination-IP step |
| TC-09 | 4/5 destination, 1 no destination-IP step | 5/5 destination |
Total 18/20 correct, **0/20 source (wrong-role) picks**; 2/20 omitted the destination-IP step (not a wrong target).
Before the fix, reversed order gave 0/5 and 0/5 (4 wrong-role picks each, remaining runs without a destination-IP step).
Not tested: validator role enforcement (unchanged), other cases, other models.
