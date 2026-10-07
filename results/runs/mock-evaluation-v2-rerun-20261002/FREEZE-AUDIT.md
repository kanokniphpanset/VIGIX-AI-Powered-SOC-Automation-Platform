# Freeze repair audit - mock-evaluation-v2-rerun-20261002

Audit/documentation only. No case was re-run, no LLM call, no recommendation, response or re-hunt was repeated. `run.json` is byte-unchanged (SHA-256 `26f06aea8ee6...`).

## 1. Official compliance definition: `OFFICIAL_V2_COMPLIANCE = 7_CRITERIA`
Evidence that `targetRole` is deliberate, not incidental:
- `EvaluationService.evaluateCompliance` computes it explicitly and ANDs it into `compliant`; `types.ts` documents it ("AND of the six mandatory criteria + targetRole").
- `test/EvaluationCompliance.test.ts` has dedicated cases (BLOCK-DESTINATION-IP aimed at the source -> NON_COMPLIANT / `targetRole=false`; correct destination -> `true`).
- It exists because of the TC-07/TC-09 source-vs-destination requirement (PSI-5, `networkRole` fix) and the Mock v2 task text ("target role where applicable", "do not count a recommendation compliant merely because it contains a related IOC").
- Names in code (the authoritative list): attackAlignment, evidenceSupport, knowledgeValidity, policyCompliance, playbookAlignment, approvalCorrectness, **targetRole**. (The shorthand "action / target / evidence / catalog / policy / playbook / targetRole" maps onto these; `approvalCorrectness` is the original sixth criterion.)
- Recomputed from `run.json`: 9/9 compliant under 7 criteria and 9/9 under the original 6; `targetRole` 9/9. Verdicts and the aggregate do not change.

## 2. Documentation repaired (labels/metadata only)
`metrics/final-kpi-summary.json` ("six-criterion" -> seven-criterion incl. targetRole; `freezeAnnotations`), `metrics/final-recommendation-compliance.json` (`criteria.targetRole` 9/9 from `run.json`, mapping entry, definition, annotations), `REPORT.md` (compliance label and section I). No result, numerator, denominator, case result or ground truth was changed.

## 3. Provenance
`code-under-test-manifest.txt`: SHA-256, purpose and result-impact for every file differing from `f3114be`, including the untracked files outside `code-under-test.diff`. Tracked-diff hash `f6b5951b55b12db0` is unchanged since before the run. Code is still uncommitted; committing it (and recording the commit) is the cleanest way to make the freeze permanent.

## 4. TC-08 `evidenceLimits`
TC-08 evidenceLimits contains stale documentation: the extractor statement about data.audit.* is outdated relative to current code. This text does not affect scoring. Ground truth and its hash `e54d003515bdcb19` were not touched.

## 5. Recompute of aggregates vs case level (from `run.json`, cross-checked by the earlier database cross-check with 0 differences)
| Metric | Recomputed from cases | In `final-kpi-summary.json` |
|---|---|---|
| Compliance | 9/9 | 9/9 = 100% |
| Consistency (primary) | 30/30 (`metrics/data/consistency.json`) | 30/30 = 100% (step-set, supplementary: 28/30) |
| Workflow completion | 7/9 | 7/9 = 77.78% |
| Verification (real Wazuh) | RESOLVED 7/9; TC-02, TC-10 not verified | 7/9 = 77.78% |
| Investigation time mean | 123.789 s | 123.789 |
| Decision recording latency mean | 0.057 s (2-decimal case values) | 0.056 (database, 3 decimals) - rounding only |
| IOC recall | 20/22 | per case in run.json |
| Retry | 1 case, 3 invalid generations | 1/9 = 11.11%, count 3 |
| Intervention | 1/9 (TC-03) | 1/9 = 11.11% |
| Escalation | 0 | 0 (not induced) |

## 6. Open observations (documented, not fixed)
- `final-metrics.v2.ts` supplementary target-kind check shows TC-08 ACT-KILL-PROCESS as `kindMatches=false` (first-IOC lookup; same single-kind-per-value blind spot the validator had). Not in the verdict.
- Rows of the KPI table not produced by this run: Mock Verification 10/10 (archived), Negative Validation (not available), Human/Policy Validation (0/0). HITL evidence here = `principles` checks + per-case approvals.
- TC-02 / TC-10 remain INCOMPLETE (IOC extraction / re-hunt capability limits), recorded as observed.

## Final decision
**READY_FOR_FREEZE** - the compliance definition is now stated consistently (seven criteria), provenance is recoverable from the manifest, and no result changed. Condition: freeze means these artifacts as they are now; do not edit source files afterwards without recording it, and commit the code under test when convenient.
