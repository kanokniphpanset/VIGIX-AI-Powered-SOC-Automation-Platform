# Corrections to the final evaluation report

## 2026-10-01 — IP target role was not covered by Recommendation Compliance

**What was wrong.** The report described Recommendation Compliance (9/9 = 100 %) and Recommendation Consistency (29/30) without noting that, in TC-07 and TC-09,
the ACT-BLOCK-DESTINATION-IP step targets 172.19.0.5 — the monitored endpoint's own address (the alert's `srcip`) — instead of the destination 172.19.0.7 (the C2 / exfiltration server).
The criterion `evidenceSupport` accepts any evidence-linked IOC or host, so the step was scored compliant. The "findings re-check" table (§5) therefore missed it, although the
"self-targeting IP steps" item had been on the list of things to inspect.

**What changed.** Nothing in the data. `final-evaluation-report.md` now qualifies the Compliance row, adds §5a and limitation 13; `addendum-target-role-check.json` holds the computation
(`apps/backend/scripts/eval/final/target-role-check.py`, read-only SELECT over `soar_final_eval`). The KPI JSON files are unchanged.

**What it means.** BLOCK-SOURCE-IP: 4/4 correct. BLOCK-DESTINATION-IP: 0/2 in the main/reject runs, 0/10 in the consistency repetitions. The same pattern appears in the earlier clean-v2 and intervention-v2 runs.
It must be stated as a limitation of the evaluated system; the Recommendation Compliance KPI should be cited as "validity against policy, playbook, evidence and approval rules", not as "correct targets".

## 2026-10-01 (later) — cause of the wrong IP role identified

A controlled re-run (`apps/backend/scripts/eval/extended/order-experiment.ts`, `results/extended-evaluation/data/order-experiment.json`) shows the model picks the first IP listed
among the candidate targets of BLOCK-DESTINATION-IP, and the context carries no source/destination role. With the destination listed first: the first destination-IP step was correct in 9/10 runs; with only the order reversed: 0/10 (8 source IPs, 2 runs without a destination-IP step). The listing order is whatever the database returns, which is why the final run (source first) was wrong in 12/12, while later runs (destination first) had a correct first destination-IP step in 20/20.
Note: even then 8/20 of those later recommendations ALSO listed a second destination-IP step aimed at the endpoint (172.19.0.5), with and without the runbook corpus (4/10 each), so the wrong-role pick is reduced by ordering, not eliminated.
Suggested product fixes (not applied; the evaluated code was not changed): carry the role (srcip/dstip) with each IP IOC, restrict BLOCK-DESTINATION-IP candidates to the destination IP, order candidates deterministically, and add a role check to the validator and to the compliance evaluator.
