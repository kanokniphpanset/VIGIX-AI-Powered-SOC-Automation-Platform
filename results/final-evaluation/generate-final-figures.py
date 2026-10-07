#!/usr/bin/env python3
"""Figures for the FINAL evaluation (matplotlib only; default colours; no styles). Reads ONLY the final-*.json files
written by apps/backend/scripts/eval/final/final-metrics.ts and writes PNG + PDF into ./figures/.
Run (repository root):  results/additional-evaluation/.venv/Scripts/python.exe results/final-evaluation/generate-final-figures.py
Nothing is estimated here: every plotted value is read from the JSON files; a figure is skipped (with a message) when its data is missing."""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")
os.makedirs(OUT, exist_ok=True)


def load(name):
    p = os.path.join(HERE, name)
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None


plt.rcParams.update({"font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10, "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 9,
                     "figure.dpi": 100, "savefig.dpi": 300, "savefig.facecolor": "white", "figure.facecolor": "white", "axes.facecolor": "white",
                     "pdf.fonttype": 42, "ps.fonttype": 42, "axes.spines.top": False, "axes.spines.right": False})


def save(fig, name):
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", name)


def num(v):
    return f"{v:.3f}" if abs(v) < 1 else f"{v:.2f}"


kpi = load("final-kpi-summary.json")
comp, inv, ttd = load("final-recommendation-compliance.json"), load("final-investigation-time.json"), load("final-time-to-decision.json")
cons, ver, wf = load("final-consistency.json"), load("final-verification.json"), load("final-workflow-completion.json")
per = load("final-per-test-case.json")
interv, retry = load("final-intervention-rate.json"), load("final-retry-rate.json")
if not (kpi and per):
    raise SystemExit("final-kpi-summary.json / final-per-test-case.json not found — run final-metrics.ts first")

# ---------------------------------------------------------------- Figure 1 — final KPI summary (percent metrics, denominators in the labels)
rows = [r for r in kpi["table"] if r["unit"] == "%" and isinstance(r["result"], (int, float)) and r["metric"] not in ("Mock Verification",)]
fig, ax = plt.subplots(figsize=(7.6, 4.6))
labels = [f"{r['metric']}\n({r['n'].split(';')[0] if isinstance(r['n'], str) else r['n']})" for r in rows]
bars = ax.barh(range(len(rows)), [r["result"] for r in rows])
ax.set_yticks(range(len(rows)))
ax.set_yticklabels(labels, fontsize=8)
ax.invert_yaxis()
ax.bar_label(bars, fmt="%.1f", padding=3, fontsize=8)
ax.set_xlim(0, 118)
ax.set_xticks(range(0, 101, 20))
ax.set_xlabel("Percentage (%) — numerator/denominator in the labels")
ax.set_title("Final evaluation: percentage KPIs (Real Wazuh; MOCK excluded)")
save(fig, "figure1_final_kpi_summary")


# ---------------------------------------------------------------- Figures 2 and 3 — Investigation Time, Time-to-Decision
def time_fig(data, key, title, ylabel, name):
    pc = [p for p in data["perCase"] if p["seconds"] is not None]
    if not pc:
        print("skip", name, "(no data)")
        return
    st = data["stats"]
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    bars = ax.bar([p["tc"] for p in pc], [p["seconds"] for p in pc])
    ax.bar_label(bars, labels=[num(p["seconds"]) for p in pc], fontsize=8, padding=2)
    ax.axhline(st["mean"], linestyle="--", linewidth=1, label=f"mean {num(st['mean'])} s")
    ax.axhline(st["median"], linestyle=":", linewidth=1, label=f"median {num(st['median'])} s")
    ax.set_ylabel(ylabel)
    ax.set_xlabel("Test case")
    ax.set_title(f"{title} (n = {st['n']}; SD {num(st['sd'])}, min {num(st['min'])}, max {num(st['max'])})")
    ax.legend(loc="upper right", frameon=False)
    ax.set_ylim(top=max(p["seconds"] for p in pc) * 1.3)
    save(fig, name)


time_fig(inv, "investigation", "Investigation time per case", "Investigation time (s)", "figure2_investigation_time")
time_fig(ttd, "decision", "Time-to-Decision per case (scripted IR decision)", "Time-to-Decision (s)", "figure3_time_to_decision")

# ---------------------------------------------------------------- Figure 4 — recommendation compliance (six criteria)
crit = comp["criteria"]
names = {"attackAlignment": "Action\ncorrectness", "evidenceSupport": "Target / evidence\nsupport", "knowledgeValidity": "Action catalog\nvalidity", "policyCompliance": "Policy\ncompliance", "playbookAlignment": "Playbook\nalignment", "approvalCorrectness": "Approval\ncorrectness"}
fig, ax = plt.subplots(figsize=(7.6, 4.2))
ks = list(crit.keys())
vals = [100.0 * crit[k]["passed"] / crit[k]["of"] if crit[k]["of"] else 0 for k in ks]
bars = ax.bar([names[k] for k in ks], vals)
ax.bar_label(bars, labels=[f"{crit[k]['passed']}/{crit[k]['of']}" for k in ks], fontsize=8, padding=2)
r = comp["result"]
ax.axhline(r["pct"] if r["pct"] is not None else 0, linestyle="--", linewidth=1, label=f"Recommendation Compliance {r['pct']}% ({r['numerator']}/{r['denominator']} evaluated)")
ax.set_ylim(0, 135)
ax.set_yticks(range(0, 101, 20))
ax.set_ylabel("Evaluated recommendations passing the criterion (%)")
ax.set_title(f"Recommendation compliance criteria ({r['denominatorAttemptedCases']} cases attempted)")
ax.legend(loc="upper center", frameon=False)
save(fig, "figure4_recommendation_compliance")

# ---------------------------------------------------------------- Figure 5 — recommendation consistency
if cons and cons.get("overall"):
    pcs = cons["mainActionConsistency"]
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    w = 0.38
    x = list(range(len(pcs)))
    sset = {p["tc"]: p for p in cons["stepSetConsistency"]["perCase"]}
    b1 = ax.bar([i - w / 2 for i in x], [p["pct"] for p in pcs], w, label="Main (primary) recommendation")
    b2 = ax.bar([i + w / 2 for i in x], [sset[p["tc"]]["pct"] for p in pcs], w, label="Complete step set")
    ax.bar_label(b1, labels=[f"{p['consistent']}/{p['runs']}" for p in pcs], fontsize=8, padding=2)
    ax.bar_label(b2, labels=[f"{sset[p['tc']]['runs']}/{sset[p['tc']]['of']}" for p in pcs], fontsize=8, padding=2)
    ax.set_xticks(x)
    ax.set_xticklabels([p["tc"] for p in pcs])
    ax.set_ylim(0, 135)
    ax.set_yticks(range(0, 101, 20))
    ax.set_ylabel("Consistency (%)")
    ax.set_xlabel("Test case")
    o = cons["overall"]
    ax.set_title(f"Recommendation consistency on identical evidence (pooled main {o['pct']}%, {o['numerator']}/{o['denominator']})")
    ax.legend(loc="upper center", frameon=False, ncol=2)
    save(fig, "figure5_recommendation_consistency")
else:
    print("skip figure5 (no consistency data)")

# ---------------------------------------------------------------- Figure 6 — workflow / verification outcomes (outcomes that occurred only)
real = ver["real_wazuh"]
dist = real["outcomeDistribution"]
cats = [k for k in ("RESOLVED", "NOT_RESOLVED", "NOT_CONTAINED", "SPREAD", "ESCALATED", "ERROR", "NOT_VERIFIED") if dist.get(k)]
inc = wf["incomplete"]
fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.2, 4.2), gridspec_kw={"width_ratios": [1, 1.2]})
done = wf["result"]["numerator"]
den = wf["result"]["denominator"]
bars = a1.bar(["Complete", "Incomplete"], [done, den - done])
a1.bar_label(bars, fontsize=9, padding=2)
a1.set_ylabel("Number of attempted cases")
a1.set_title(f"Workflow completion ({done}/{den})")
a1.set_ylim(0, max(done, den - done, 1) * 1.3)
bars = a2.bar(cats, [dist[k] for k in cats])
a2.bar_label(bars, fontsize=9, padding=2)
a2.set_ylabel("Number of completed responses")
a2.set_title(f"Real Wazuh verification outcome (n = {real['cases_with_completed_response']})")
a2.set_ylim(0, max(dist.values()) * 1.3)
plt.setp(a2.get_xticklabels(), rotation=15, ha="right")
save(fig, "figure6_workflow_and_verification")
