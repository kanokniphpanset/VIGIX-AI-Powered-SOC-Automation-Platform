"""Deterministic consistency metrics for the supplementary 15-repetition test.
Input : data/consistency.json (written by scripts/eval/additional/consistency.ts, unmodified repository script)
Output: metrics/*.json, cases/TC-xx/run-NN.json, run.json.  No LLM involved; exact comparison of canonical signatures only."""
import json, os, hashlib
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
src = json.load(open(os.path.join(ROOT, "data", "consistency.json"), encoding="utf8"))
runs = src["runs"]
RUN_LABEL = "supplementary-consistency-15r"
norm = lambda s: str(s).strip().lower()                      # same normalisation as the Final correctness metric (trim + lowercase)
short = lambda a: a.replace("ACT-", "")


def sig_of(r):
    pairs = {f"{short(norm(s['action']).upper())}::{norm(s['target'])}" for s in r["all_steps"]}   # set: duplicates once, order irrelevant
    return "|".join(sorted(pairs))


def aset_of(r):
    return "|".join(sorted({short(s["action"]) for s in r["all_steps"]}))


def modal(counter):
    return counter.most_common(1)[0] if counter else (None, 0)


per_case, sigs, case_ids = {}, {}, []
for cid in src["cases"]:
    rs = sorted([r for r in runs if r["case_id"] == cid], key=lambda r: r["repetition"])
    case_ids.append(cid)
    valid = [r for r in rs if r["recommendation_status"] == "VALIDATED"]
    failed = [r for r in rs if r["recommendation_status"] != "VALIDATED"]
    for r in rs:
        r["run_id"] = f"{RUN_LABEL}:{cid}:r{r['repetition']:02d}"
        r["signature"] = sig_of(r) if r in valid else None
        os.makedirs(os.path.join(ROOT, "cases", cid), exist_ok=True)
        json.dump(r, open(os.path.join(ROOT, "cases", cid, f"run-{r['repetition']:02d}.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)
    core = Counter(sig_of(r) for r in valid)
    aset = Counter(aset_of(r) for r in valid)
    play = Counter(r["playbook_id"] for r in valid)
    play_all = Counter(r["playbook_id"] for r in rs)
    # target consistency: pair-level agreement of the target chosen for each action
    tgt = defaultdict(Counter)
    for r in valid:
        for s in r["all_steps"]:
            tgt[short(s["action"])][norm(s["target"])] += 1
    pair_total = sum(sum(c.values()) for c in tgt.values())
    pair_modal = sum(c.most_common(1)[0][1] for c in tgt.values())
    (msig, mn), (mact, an), (mpl, pn) = modal(core), modal(aset), modal(play)
    attempts = [r["attempts"] for r in rs]
    per_case[cid] = dict(
        totalRuns=len(rs), validRecommendationRuns=len(valid), failedGenerationRuns=len(failed),
        validationFailureRuns=sum(1 for r in failed if r["failure_reason"] == "INVALID_AI_OUTPUT"),
        timeoutOrErrorRuns=sum(1 for r in failed if r["failure_reason"] != "INVALID_AI_OUTPUT"),
        generationSuccess=dict(num=len(valid), den=len(rs), pct=round(100 * len(valid) / len(rs), 2)),
        coreConsistency=dict(modalSignature=msig, modalCount=mn, den=len(valid), pct=round(100 * mn / len(valid), 2) if valid else None,
                             conservativePct_overAllRuns=round(100 * mn / len(rs), 2), distinctSignatures=len(core)),
        actionSetConsistency=dict(modalActionSet=mact, num=an, den=len(valid), pct=round(100 * an / len(valid), 2) if valid else None, distinct=len(aset)),
        targetConsistency=dict(num=pair_modal, den=pair_total, pct=round(100 * pair_modal / pair_total, 2) if pair_total else None,
                               perAction={a: dict(modalTarget=c.most_common(1)[0][0], num=c.most_common(1)[0][1], den=sum(c.values()), distinctTargets=len(c)) for a, c in tgt.items()}),
        playbookConsistency=dict(modalPlaybook=mpl, num=pn, den=len(valid), pct=round(100 * pn / len(valid), 2) if valid else None,
                                 allRuns=dict(play_all), note="playbook_id is recorded for failed runs too (from the context); the metric uses valid runs as denominator"),
        firstPass=dict(num=sum(1 for r in rs if r["recommendation_status"] == "VALIDATED" and r["attempts"] == 1), den=len(rs)),
        meanRetryCount=dict(value=round(sum(a - 1 for a in attempts) / len(attempts), 3), definition="mean(agent calls - 1) over all runs; agent call = one LLM generation (initial or the single bounded correction)"),
        runsWithRetry=sum(1 for a in attempts if a > 1),
        failedRuns=[dict(run_id=r["run_id"], repetition=r["repetition"], reason=r["failure_reason"], attempts=r["attempts"], violations=r["violations"]) for r in failed],
        evidenceSnapshotIdentical=len(set(r["evidence_snapshot_hash"] for r in rs)) == 1,
        evidenceSnapshotHash=sorted(set(r["evidence_snapshot_hash"] for r in rs)),
    )
    sigs[cid] = dict(validRuns=len(valid), signatures=[dict(signature=s, count=n, share=f"{n}/{len(valid)}", runs=[r["run_id"] for r in valid if sig_of(r) == s]) for s, n in core.most_common()],
                     notValidRuns=[r["run_id"] for r in failed])

# overall (pooled, denominators explicit)
tot = sum(p["totalRuns"] for p in per_case.values())
val = sum(p["validRecommendationRuns"] for p in per_case.values())
pool = lambda k: (sum(p[k]["num"] for p in per_case.values()), sum(p[k]["den"] for p in per_case.values()))
core_n = sum(p["coreConsistency"]["modalCount"] for p in per_case.values())
a_n, a_d = pool("actionSetConsistency")
t_n, t_d = pool("targetConsistency")
pl_n, pl_d = pool("playbookConsistency")
fp_n, fp_d = pool("firstPass")
pct = lambda n, d: round(100 * n / d, 2) if d else None
overall = dict(
    totalRuns=tot, totalValidRecommendationRuns=val,
    failedGenerationRuns=tot - val,
    validationFailureRuns=sum(p["validationFailureRuns"] for p in per_case.values()), timeoutOrErrorRuns=sum(p["timeoutOrErrorRuns"] for p in per_case.values()),
    generationSuccess=dict(num=val, den=tot, pct=pct(val, tot)),
    coreRecommendationConsistency=dict(num=core_n, den=val, pct=pct(core_n, val), note="pooled: sum of per-case modal counts / total valid runs; conservative over-all-runs value = %s" % pct(core_n, tot)),
    actionSetConsistency=dict(num=a_n, den=a_d, pct=pct(a_n, a_d)),
    targetConsistency=dict(num=t_n, den=t_d, pct=pct(t_n, t_d), note="pair-level: action-target pairs whose target equals the modal target of that action, per case"),
    playbookConsistency=dict(num=pl_n, den=pl_d, pct=pct(pl_n, pl_d)),
    firstPass=dict(num=fp_n, den=fp_d, pct=pct(fp_n, fp_d)),
    meanRetryCount=round(sum(p["meanRetryCount"]["value"] * p["totalRuns"] for p in per_case.values()) / tot, 3),
    macroMeanCoreConsistencyPct=round(sum(p["coreConsistency"]["pct"] for p in per_case.values()) / len(per_case), 2),
)
os.makedirs(os.path.join(ROOT, "metrics"), exist_ok=True)
json.dump(per_case, open(os.path.join(ROOT, "metrics", "per-case-metrics.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)
json.dump(sigs, open(os.path.join(ROOT, "metrics", "recommendation-signatures.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)
json.dump(dict(run=RUN_LABEL, source="scripts/eval/additional/consistency.ts (unmodified), EVAL_SOURCE_RUN=final-evaluation-v3.3", definition="canonical signature = sorted set of ACTION::target (trim+lowercase, duplicates once, order ignored); exact comparison; no LLM judge",
               overall=overall, perCase={c: {k: v for k, v in p.items() if k in ("totalRuns", "validRecommendationRuns", "generationSuccess", "coreConsistency", "actionSetConsistency", "targetConsistency", "playbookConsistency", "firstPass", "meanRetryCount")} for c, p in per_case.items()},
               unchangedByThisTest="Final Evaluation v3.3 Correct Recommendation 4/10 = 40.00 %"),
          open(os.path.join(ROOT, "metrics", "consistency-summary.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)
json.dump(src, open(os.path.join(ROOT, "run.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)
print(json.dumps(overall, indent=1))
for c, p in per_case.items():
    print(c, p["validRecommendationRuns"], p["generationSuccess"]["pct"], p["coreConsistency"]["pct"], p["actionSetConsistency"]["pct"], p["targetConsistency"]["pct"], p["playbookConsistency"]["pct"], p["firstPass"], p["meanRetryCount"]["value"], p["evidenceSnapshotIdentical"])
    print("   ", sigs[c]["signatures"][0]["signature"], sigs[c]["signatures"][0]["share"], "| invalid:", sigs[c]["notValidRuns"])
