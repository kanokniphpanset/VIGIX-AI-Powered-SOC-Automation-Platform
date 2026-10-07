#!/usr/bin/env python3
"""Paper figures for the VIGIX additional evaluation.

Reads ONLY results/additional-evaluation/figure-data.json (produced from the measured results by
apps/backend/scripts/eval/additional/build-paper-outputs.ts) and writes PNG + PDF files to ./figures/.
matplotlib only: no seaborn, no custom colours, no matplotlib styles (default colour cycle). Bar charts only.
Nothing is estimated here: every plotted value is copied from the data file.

Run (from the repository root, using the local virtualenv that holds matplotlib):
    results/additional-evaluation/.venv/Scripts/python.exe results/additional-evaluation/generate-paper-figures.py
"""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(HERE, "figure-data.json"), encoding="utf-8") as fh:
    D = json.load(fh)

plt.rcParams.update({
    "font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10, "xtick.labelsize": 9, "ytick.labelsize": 9,
    "legend.fontsize": 9, "figure.dpi": 100, "savefig.dpi": 300, "savefig.facecolor": "white",
    "figure.facecolor": "white", "axes.facecolor": "white", "pdf.fonttype": 42, "ps.fonttype": 42,
    "axes.spines.top": False, "axes.spines.right": False,
})


def num(v):
    """2 decimals for values >= 1 s, 3 decimals for sub-second values (baseline latencies)."""
    return f"{v:.3f}" if abs(v) < 1 else f"{v:.2f}"


def save(fig, name):
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", name)


# ---------------------------------------------------------------- Figure 1 — main evaluation metrics (Clean Run)
f1 = D["fig1_main_metrics"]
labels = [m["label"] for m in f1["metrics"]]
att = [m["attempted_pct"] for m in f1["metrics"]]
ev = [m["evaluated_pct"] for m in f1["metrics"]]
fig, ax = plt.subplots(figsize=(7.2, 4.0))
w = 0.38
x = list(range(len(labels)))
b1 = ax.bar([i - w / 2 for i in x], att, w, label=f"Denominator: attempted cases (n={f1['n_attempted']})")
ev_x = [i + w / 2 for i, v in zip(x, ev) if v is not None]
ev_v = [v for v in ev if v is not None]
b2 = ax.bar(ev_x, ev_v, w, label=f"Denominator: evaluated recommendations (n={f1['n_evaluated']})")
ax.bar_label(b1, fmt="%.1f", fontsize=8, padding=2)
ax.bar_label(b2, fmt="%.1f", fontsize=8, padding=2)
ax.set_xticks(x)
ax.set_xticklabels(labels, rotation=15, ha="right")
ax.set_ylabel("Percentage of cases (%)")
ax.set_ylim(0, 150)
ax.set_yticks(range(0, 101, 20))  # percentages: no ticks above 100 (the headroom only hosts the legend)
ax.set_title("Main evaluation metrics, Real Wazuh Clean Run")
ax.legend(loc="upper center", frameon=False)
save(fig, "figure1_main_metrics")

# ---------------------------------------------------------------- Figure 2 — clean vs intervention
f2 = D["fig2_clean_vs_intervention"]
fig, ax = plt.subplots(figsize=(6.4, 4.0))
names = [m["label"] for m in f2["metrics"]]
x = list(range(len(names)))
c = [m["clean_pct"] for m in f2["metrics"]]
i = [m["intervention_pct"] for m in f2["metrics"]]
b1 = ax.bar([k - w / 2 for k in x], c, w, label=f"Clean Run (n={f2['n_clean']})")
b2 = ax.bar([k + w / 2 for k in x], i, w, label=f"Intervention Run (n={f2['n_intervention']})")
ax.bar_label(b1, fmt="%.1f", fontsize=8, padding=2)
ax.bar_label(b2, fmt="%.1f", fontsize=8, padding=2)
ax.set_xticks(x)
ax.set_xticklabels(names)
ax.set_ylabel("Percentage of attempted cases (%)")
ax.set_ylim(0, 140)
ax.set_yticks(range(0, 101, 20))  # percentages: no ticks above 100 (the headroom only hosts the legend)
ax.set_title("Clean Run versus Intervention Run")
ax.legend(loc="upper center", frameon=False)
save(fig, "figure2_clean_vs_intervention")

# ---------------------------------------------------------------- Figure 3 — investigation time
f3 = D["fig3_investigation_time"]
fig, ax = plt.subplots(figsize=(7.2, 4.2))
conds = f3["conditions"]
xs = list(range(len(conds)))
means = [c_["mean"] for c_ in conds]
bars = ax.bar(xs, means)
for k, c_ in enumerate(conds):
    pts = c_["values"]
    ax.scatter([k] * len(pts), pts, s=14, zorder=3, color="black", alpha=0.7)
    ax.annotate(f"mean {num(c_['mean'])} s\nmedian {num(c_['median'])}, SD {num(c_['sd'])}\nmin {num(c_['min'])}, max {num(c_['max'])}\nn = {c_['n']}",
                (k, c_["max"]), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=7.5)
ax.set_yscale("log")
ax.set_xticks(xs)
ax.set_xticklabels([c_["label"] for c_ in conds])
ax.set_ylabel("Investigation time (s, log scale)")
ax.set_ylim(top=max(c_["max"] for c_ in conds) * 12)
ax.set_title("Investigation time by condition (bars: mean; dots: individual cases)")
save(fig, "figure3_investigation_time")

# ---------------------------------------------------------------- Figure 4 — recommendation consistency
f4 = D["fig4_consistency"]
fig, ax = plt.subplots(figsize=(6.8, 4.0))
cases = [c_["case"] for c_ in f4["cases"]]
vals = [c_["consistency_pct"] for c_ in f4["cases"]]
bars = ax.bar(cases, vals)
ax.bar_label(bars, labels=[f"{c_['consistent']}/{c_['runs']}" for c_ in f4["cases"]], fontsize=8, padding=2)
ax.axhline(f4["overall_pct"], linestyle="--", linewidth=1, label=f"Pooled: {f4['overall_pct']:.1f}% ({f4['overall_consistent']}/{f4['overall_runs']} runs)")
ax.set_ylabel("Consistency (%)")
ax.set_xlabel("Test case")
ax.set_ylim(0, 135)
ax.set_yticks(range(0, 101, 20))  # percentages: no ticks above 100 (the headroom only hosts the legend)
ax.set_title(f"Recommendation consistency over {f4['repetitions']} repetitions on identical evidence")
ax.legend(loc="upper center", frameon=False)
save(fig, "figure4_recommendation_consistency")

# ---------------------------------------------------------------- Figure 5 — verification outcomes (only outcomes that occurred)
f5 = D["fig5_verification_outcomes"]
fig, ax = plt.subplots(figsize=(6.8, 4.0))
groups = [g["label"] for g in f5["groups"]]
cats = f5["categories_observed"]
bottoms = [0] * len(groups)
for cat in cats:
    h = [g["counts"].get(cat, 0) for g in f5["groups"]]
    bars = ax.bar(groups, h, bottom=bottoms, label=cat)
    for rect, hv, bt in zip(bars, h, bottoms):
        if hv:
            ax.text(rect.get_x() + rect.get_width() / 2, bt + hv / 2, str(hv), ha="center", va="center", fontsize=8)
    bottoms = [b + hv for b, hv in zip(bottoms, h)]
ax.set_ylabel("Number of completed responses")
ax.set_xlabel("Evaluation condition")
ax.set_ylim(0, max(bottoms) * 1.35)
ax.set_title("Verification outcomes (only outcomes that occurred are shown)")
ax.legend(title="Verification outcome", loc="upper right", frameon=False)
save(fig, "figure5_verification_outcomes")

# ---------------------------------------------------------------- Figure 6 — negative validation
f6 = D["fig6_negative_validation"]
fig, ax = plt.subplots(figsize=(5.6, 4.0))
labs = ["Rejected unsupported\nrecommendations", "Accepted unsupported\nrecommendations"]
vals = [f6["rejected"], f6["accepted"]]
bars = ax.bar(labs, vals)
ax.bar_label(bars, fontsize=9, padding=2)
ax.set_ylabel("Invalid recommendations (count)")
ax.set_ylim(0, max(vals) * 1.25 + 1)
ax.set_title(f"Negative validation ({f6['total']} controlled invalid recommendations)")
save(fig, "figure6_negative_validation")
