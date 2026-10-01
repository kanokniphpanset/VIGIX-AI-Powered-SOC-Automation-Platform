"""
make-figures.py — publication figures for the VIGIX recommendation-evaluation results.
Reads apps/backend/scripts/eval-out/*.json and writes PNG (300 dpi) + PDF (vector) into figures/.
Palette validated with the dataviz skill's checker (blue #0089b3 / orange #cc6a12 CVD-safe; green #1f7a4d status).

Run:  apps/ai-orchestrator/.venv/Scripts/python.exe apps/backend/scripts/make-figures.py
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")
os.makedirs(OUT, exist_ok=True)

# ---- palette (validated) ----
BLUE, ORANGE, GREEN = "#0089b3", "#cc6a12", "#1f7a4d"
INK, MUTED, GRID, SURF = "#1a2230", "#5b6675", "#d8dee5", "#ffffff"

plt.rcParams.update({
    "figure.dpi": 120, "savefig.dpi": 300, "figure.facecolor": SURF, "axes.facecolor": SURF,
    "font.family": "DejaVu Sans", "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold",
    "axes.labelsize": 10.5, "axes.edgecolor": MUTED, "axes.linewidth": 0.8, "text.color": INK,
    "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.7, "axes.axisbelow": True,
})

rep = json.load(open(os.path.join(HERE, "eval-out", "repeated-evaluation-N2.json")))
per = rep["perCase"]
tcs = [c["tc"] for c in per]
labels = [t.replace("TC-", "") for t in tcs]
N = rep["runs"]

def save(fig, name):
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), bbox_inches="tight", facecolor=SURF)
    plt.close(fig)
    print("wrote", name + ".png / .pdf")

# ===== Fig 1: Investigation (recommendation-generation) time per case, mean +/- SD =====
inv = [c["investigationMean"] for c in per]
sd = [c["investigationSd"] for c in per]
fig, ax = plt.subplots(figsize=(7.2, 4.0))
bars = ax.bar(labels, inv, yerr=sd, capsize=3.5, color=BLUE, width=0.66,
              error_kw=dict(ecolor=MUTED, elinewidth=1.1), zorder=3)
m = rep["overall"]["investigationTimeMean"]
ax.axhline(m, color=ORANGE, ls="--", lw=1.3, zorder=2, label=f"overall mean {m:.1f}s")
for b, v in zip(bars, inv):
    ax.text(b.get_x() + b.get_width()/2, v + max(sd)*0.06 + 1.5, f"{v:.0f}", ha="center", va="bottom", fontsize=8.3, color=INK)
ax.set_ylabel("Time to recommendation (s)")
ax.set_xlabel("Attack case (TC)")
ax.set_title(f"Recommendation-generation time per case (mean ± SD, N={N})")
ax.set_ylim(0, max(v+s for v, s in zip(inv, sd))*1.18)
ax.grid(axis="x", visible=False)
ax.legend(frameon=False, loc="upper right", fontsize=9)
for sp in ("top", "right"):
    ax.spines[sp].set_visible(False)
save(fig, "fig1_investigation_time")

# ===== Fig 2: Compliance check matrix (10 cases x 6 criteria) =====
checks = ["Attack\nalignment", "Evidence\nsupport", "Knowledge\nvalidity", "Policy\ncompliance", "Playbook\nalignment", "Approval\ncorrectness"]
fig, ax = plt.subplots(figsize=(7.6, 4.2))
nrow, ncol = len(tcs), len(checks)
for i in range(nrow):
    for j in range(ncol):
        ax.add_patch(plt.Rectangle((j, nrow-1-i), 1, 1, facecolor=GREEN, edgecolor=SURF, linewidth=2, zorder=2))
        ax.text(j+0.5, nrow-1-i+0.5, "✓", ha="center", va="center", color="white", fontsize=12, fontweight="bold", zorder=3)
ax.set_xlim(0, ncol); ax.set_ylim(0, nrow)
ax.set_xticks([j+0.5 for j in range(ncol)]); ax.set_xticklabels(checks, fontsize=8.6)
ax.set_yticks([nrow-1-i+0.5 for i in range(nrow)]); ax.set_yticklabels(tcs, fontsize=9)
ax.tick_params(length=0)
for sp in ax.spines.values():
    sp.set_visible(False)
ax.grid(False)
ax.set_title("Recommendation compliance: all six criteria pass for every case")
ax.legend(handles=[Patch(facecolor=GREEN, label="PASS (COMPLIANT)")], frameon=False, loc="upper left", bbox_to_anchor=(0, -0.08), fontsize=9)
save(fig, "fig2_compliance_matrix")

# ===== Fig 3: Compliance rate - as-is vs automatic (steady-state) =====
fig, ax = plt.subplots(figsize=(5.0, 4.0))
cats = ["As-is\n(after any\nintervention)", "Automatic\n(steady-state,\nno intervention)"]
vals = [100.0, 80.0]
bars = ax.bar(cats, vals, color=[BLUE, ORANGE], width=0.56, zorder=3)
for b, v, n in zip(bars, vals, ["10/10", "8/10"]):
    ax.text(b.get_x()+b.get_width()/2, v+1.2, f"{v:.0f}%\n({n})", ha="center", va="bottom", fontsize=9.5, color=INK)
ax.set_ylabel("Recommendation compliance (%)")
ax.set_ylim(0, 112)
ax.set_title("Recommendation compliance rate")
ax.grid(axis="x", visible=False)
for sp in ("top", "right"):
    ax.spines[sp].set_visible(False)
save(fig, "fig3_compliance_rate")

# ===== Fig 4: Intervention classification per case (honest findings) =====
# category per case: none / analyst IOC (per-run) / one-time KB fix
cat_of = {"TC-03": "ioc", "TC-08": "ioc", "TC-07": "kb", "TC-09": "kb"}
colmap = {"none": GREEN, "ioc": ORANGE, "kb": BLUE}
hatch = {"none": "", "ioc": "", "kb": "//"}
heights = {"none": 1, "ioc": 1, "kb": 1}
fig, ax = plt.subplots(figsize=(7.2, 3.3))
for idx, tc in enumerate(tcs):
    k = cat_of.get(tc, "none")
    ax.bar(idx, heights[k], color=colmap[k], width=0.66, hatch=hatch[k], edgecolor="white", linewidth=0.8, zorder=3)
ax.set_xticks(range(len(tcs))); ax.set_xticklabels(labels)
ax.set_yticks([])
ax.set_ylim(0, 1.35)
ax.set_xlabel("Attack case (TC)")
ax.set_title("Intervention needed before a compliant recommendation")
ax.grid(False)
for sp in ("top", "right", "left"):
    ax.spines[sp].set_visible(False)
legend = [Patch(facecolor=GREEN, label="None (automatic): 6 cases"),
          Patch(facecolor=ORANGE, label="Analyst IOC, per run: TC-03, TC-08"),
          Patch(facecolor=BLUE, hatch="//", label="One-time KB fix: TC-07, TC-09")]
ax.legend(handles=legend, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=1, fontsize=8.8)
save(fig, "fig4_intervention_per_case")

print("\nAll figures in:", OUT)
