"""
render-figures.py — render the 6 paper figures from the FROZEN real-Wazuh results.
Reads figure-data.json (next to this file) and writes PNG (300 dpi) + PDF into figures/.
Captions: see figure-captions.md. Palette validated CVD-safe (blue #0089b3 / orange #cc6a12);
status colours for Fig 5 (green/amber/red) carry text labels.

Run:  apps/ai-orchestrator/.venv/Scripts/python.exe results/additional-evaluation/render-figures.py
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")
os.makedirs(OUT, exist_ok=True)
D = json.load(open(os.path.join(HERE, "figure-data.json")))

BLUE, ORANGE, GREEN = "#0089b3", "#cc6a12", "#1f7a4d"
RED, AMBER = "#a8322d", "#c99a1e"
INK, MUTED, GRID, SURF = "#1a2230", "#5b6675", "#dde3ea", "#ffffff"

plt.rcParams.update({
    "figure.dpi": 120, "savefig.dpi": 300, "figure.facecolor": SURF, "axes.facecolor": SURF,
    "font.family": "DejaVu Sans", "font.size": 10, "axes.titlesize": 11.5, "axes.titleweight": "bold",
    "axes.labelsize": 10, "axes.edgecolor": MUTED, "axes.linewidth": 0.8, "text.color": INK,
    "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.7, "axes.axisbelow": True,
})

def save(fig, name):
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), bbox_inches="tight", facecolor=SURF)
    plt.close(fig)
    print("wrote", name)

def nolrt(ax):
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)

# ===== Fig 1: Main metrics (Clean Run) — attempted (n=9) vs validated (n=7) =====
f = D["fig1_main_metrics"]
labels = [m["label"] for m in f["metrics"]]
att = [m["attempted_pct"] for m in f["metrics"]]
ev = [m["evaluated_pct"] for m in f["metrics"]]
x = np.arange(len(labels)); w = 0.38
fig, ax = plt.subplots(figsize=(7.6, 4.2))
b1 = ax.bar(x - w/2, att, w, color=BLUE, label=f"% of attempted cases (n={f['n_attempted']})", zorder=3)
ev_x = [xi + w/2 for xi, e in zip(x, ev) if e is not None]
ev_v = [e for e in ev if e is not None]
b2 = ax.bar(ev_x, ev_v, w, color=ORANGE, label=f"% of validated recommendations (n={f['n_evaluated']})", zorder=3)
for b in list(b1) + list(b2):
    ax.text(b.get_x()+b.get_width()/2, b.get_height()+1.5, f"{b.get_height():.1f}", ha="center", va="bottom", fontsize=8.2)
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
ax.set_ylabel("Percent (%)"); ax.set_ylim(0, 112)
ax.set_title("Figure 1  Main evaluation metrics — Real Wazuh, Clean Run")
ax.grid(axis="x", visible=False); nolrt(ax)
ax.legend(frameon=False, fontsize=8.6, loc="lower center", bbox_to_anchor=(0.5, -0.32), ncol=1)
save(fig, "fig1_main_metrics")

# ===== Fig 2: Clean vs Intervention =====
f = D["fig2_clean_vs_intervention"]
labels = [m["label"] for m in f["metrics"]]
clean = [m["clean_pct"] for m in f["metrics"]]
intv = [m["intervention_pct"] for m in f["metrics"]]
x = np.arange(len(labels)); w = 0.38
fig, ax = plt.subplots(figsize=(6.0, 4.2))
b1 = ax.bar(x - w/2, clean, w, color=BLUE, label=f"Clean Run (n={f['n_clean']})", zorder=3)
b2 = ax.bar(x + w/2, intv, w, color=ORANGE, label=f"Intervention Run (n={f['n_intervention']})", zorder=3)
for b in list(b1)+list(b2):
    ax.text(b.get_x()+b.get_width()/2, b.get_height()+1.5, f"{b.get_height():.1f}", ha="center", va="bottom", fontsize=8.4)
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9.2)
ax.set_ylabel("Percent of attempted cases (%)"); ax.set_ylim(0, 112)
ax.set_title("Figure 2  Clean Run vs Intervention Run")
ax.grid(axis="x", visible=False); nolrt(ax)
ax.legend(frameon=True, facecolor=SURF, edgecolor=GRID, framealpha=0.95, fontsize=8.8, loc="upper right")
fig.text(0.5, -0.02, "Intervention Run is an analyst-assisted condition — not the system's unaided performance.",
         ha="center", fontsize=7.8, color=MUTED, style="italic")
save(fig, "fig2_clean_vs_intervention")

# ===== Fig 3: Investigation time (log scale) — baseline / Clean / Intervention =====
f = D["fig3_investigation_time"]
conds = f["conditions"]
labels = [c["label"] for c in conds]
means = [c["mean"] for c in conds]
x = np.arange(len(conds))
fig, ax = plt.subplots(figsize=(7.2, 4.4))
cols = [MUTED, BLUE, ORANGE]
ax.bar(x, means, 0.52, color=cols, zorder=2, alpha=0.9)
for xi, c in zip(x, conds):
    jitter = (np.random.RandomState(1).rand(len(c["values"])) - 0.5) * 0.22
    ax.scatter(xi + jitter, c["values"], s=20, color=INK, alpha=0.65, zorder=4, edgecolors="white", linewidths=0.4)
    ax.annotate(f"mean {c['mean']:.2f}s\nmed {c['median']:.2f} · SD {c['sd']:.2f}\n[{c['min']:.3g}–{c['max']:.3g}] n={c['n']}",
                (xi, c["max"]), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=7.4, color=INK)
ax.set_yscale("log")
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
ax.set_ylabel("Time to proposed response (s, log scale)")
ax.set_title("Figure 3  Investigation time: baseline vs VIGIX", pad=10)
ax.set_ylim(0.005, 2500)
ax.grid(axis="x", visible=False); nolrt(ax)
fig.text(0.5, -0.02, "Baseline is a non-AI machine procedure latency, not an analyst benchmark; no significance implied.",
         ha="center", fontsize=7.8, color=MUTED, style="italic")
save(fig, "fig3_investigation_time")

# ===== Fig 4: Consistency (5 reps x 6 cases; pooled 29/30) =====
f = D["fig4_consistency"]
cases = [c["case"] for c in f["cases"]]
pct = [c["consistency_pct"] for c in f["cases"]]
fig, ax = plt.subplots(figsize=(7.0, 4.0))
bars = ax.bar(cases, pct, 0.6, color=BLUE, zorder=3)
for b, c in zip(bars, f["cases"]):
    ax.text(b.get_x()+b.get_width()/2, b.get_height()+1.2, f"{c['consistency_pct']:.0f}%\n({c['consistent']}/{c['runs']})", ha="center", va="bottom", fontsize=8)
ax.axhline(f["overall_pct"], color=ORANGE, ls="--", lw=1.4, zorder=2,
           label=f"pooled {f['overall_pct']:.2f}% ({f['overall_consistent']}/{f['overall_runs']})")
ax.set_ylabel("Primary-recommendation consistency (%)")
ax.set_ylim(0, 115)
ax.set_title(f"Figure 4  Recommendation consistency ({f['repetitions']} repetitions on identical evidence)")
ax.grid(axis="x", visible=False); nolrt(ax)
ax.legend(frameon=False, fontsize=9, loc="lower center")
save(fig, "fig4_consistency")

# ===== Fig 5: Verification outcomes (stacked) =====
f = D["fig5_verification_outcomes"]
groups = f["groups"]
labels = [g["label"] for g in groups]
cats = ["RESOLVED", "ERROR", "NOT_RESOLVED"]
cmap = {"RESOLVED": GREEN, "ERROR": AMBER, "NOT_RESOLVED": RED}
x = np.arange(len(groups))
fig, ax = plt.subplots(figsize=(6.4, 4.2))
bottom = np.zeros(len(groups))
for cat in cats:
    vals = np.array([g["counts"].get(cat, 0) for g in groups], dtype=float)
    ax.bar(x, vals, 0.55, bottom=bottom, color=cmap[cat], label=cat, zorder=3, edgecolor="white", linewidth=1)
    for xi, v, b in zip(x, vals, bottom):
        if v > 0:
            ax.text(xi, b + v/2, f"{int(v)}", ha="center", va="center", color="white", fontsize=9.5, fontweight="bold")
    bottom += vals
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
ax.set_ylabel("Number of (simulated) responses")
ax.set_ylim(0, max(bottom)+1.2)
ax.set_title("Figure 5  Real Wazuh re-hunt verification outcomes")
ax.grid(axis="x", visible=False); nolrt(ax)
ax.legend(frameon=False, fontsize=8.6, loc="upper right", ncol=1)
fig.text(0.5, -0.02, "RESOLVED = no specified recurrence detected in the tested window (not proof of eradication); ERROR = no searchable IOC.",
         ha="center", fontsize=7.2, color=MUTED, style="italic")
save(fig, "fig5_verification_outcomes")

# ===== Fig 6: Negative validation (10 invalid -> rejected/accepted) =====
f = D["fig6_negative_validation"]
fig, ax = plt.subplots(figsize=(5.2, 4.0))
bars = ax.bar(["Rejected\n(correct)", "Accepted\n(leak)"], [f["rejected"], f["accepted"]], 0.5, color=[GREEN, RED], zorder=3)
for b, v in zip(bars, [f["rejected"], f["accepted"]]):
    ax.text(b.get_x()+b.get_width()/2, b.get_height()+0.15, str(v), ha="center", va="bottom", fontsize=12, fontweight="bold")
ax.set_ylabel(f"Count of controlled invalid recommendations (total {f['total']})")
ax.set_ylim(0, f["total"]+1.5)
ax.set_title("Figure 6  Negative validation (validator rejection)")
ax.grid(axis="x", visible=False); nolrt(ax)
fig.text(0.5, -0.02, "Each is a validated candidate with one injected fault; tests rule coverage, not AI accuracy.",
         ha="center", fontsize=7.6, color=MUTED, style="italic")
save(fig, "fig6_negative_validation")

print("\nAll 6 figures in:", OUT)
