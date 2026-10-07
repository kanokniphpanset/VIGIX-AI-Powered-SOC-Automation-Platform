#!/usr/bin/env python3
"""Figures for the EXTENDED evaluation (matplotlib only, default colours). Reads ONLY extended-*.json / data/order-experiment.json.
Run (repo root): results/additional-evaluation/.venv/Scripts/python.exe results/extended-evaluation/generate-extended-figures.py"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures"); os.makedirs(OUT, exist_ok=True)
load = lambda n: json.load(open(os.path.join(HERE, n), encoding="utf-8")) if os.path.exists(os.path.join(HERE, n)) else None
plt.rcParams.update({"font.size": 10, "axes.titlesize": 11, "savefig.dpi": 300, "savefig.facecolor": "white", "figure.facecolor": "white", "axes.facecolor": "white", "pdf.fonttype": 42, "axes.spines.top": False, "axes.spines.right": False})

def save(fig, name):
    fig.tight_layout()
    for ext in ("png", "pdf"): fig.savefig(os.path.join(OUT, f"{name}.{ext}"), bbox_inches="tight")
    plt.close(fig); print("wrote", name)

lf, esc, rag, order = load("extended-low-fp.json"), load("extended-escalation.json"), load("extended-rag.json"), load("data/order-experiment.json")

# 1 — LOW / FP: checks passed per case, labelled with Wazuh level and resulting severity
if lf:
    cs = lf["cases"]; fig, ax = plt.subplots(figsize=(8.2, 4.2))
    ps = [int(c["harnessChecks"].split("/")[0]) for c in cs]; tot = [int(c["harnessChecks"].split("/")[1]) for c in cs]
    labels = [f"{c['case']}\nL{c['level']} → {c['severityDb']}" for c in cs]
    ax.bar(range(len(cs)), tot, label="checks defined"); b = ax.bar(range(len(cs)), ps, label="checks passed", width=0.5)
    ax.bar_label(b, labels=[f"{p}/{t}" for p, t in zip(ps, tot)], fontsize=8, padding=2)
    ax.set_xticks(range(len(cs))); ax.set_xticklabels(labels, fontsize=8); ax.set_ylabel("Handling checks (database-verified)")
    ax.set_title("LOW severity and False-Positive handling: checks per case"); ax.legend(frameon=False, loc="upper left"); ax.set_ylim(0, max(tot) * 1.25)
    save(fig, "figure1_low_false_positive")

# 2 — ESCALATED: matching events per re-hunt round, investigation number reopened
if esc:
    v = esc["verifications"]; fig, ax = plt.subplots(figsize=(6.6, 4.0))
    b = ax.bar([f"Round {x['round']}" for x in v], [x["matchingEvents"] for x in v])
    ax.bar_label(b, labels=[f"{x['result']}" for x in v], fontsize=8, padding=2)
    ax.set_ylabel("Matching events in the REAL_WAZUH re-hunt"); ax.set_ylim(0, max(x["matchingEvents"] for x in v) * 1.4)
    ax.set_title(f"ESCALATED path: {esc['incidentFinal']['status']} after round {len(v)} (investigation #{esc['incidentFinal']['investigationNumber']})")
    save(fig, "figure2_escalated_path")

# 3 — RAG: retrieval rank per case (arm B) + paired outcome counts
if rag:
    B = rag["arms"]["B_runbook_corpus"]; A = rag["arms"]["A_empty_corpus"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4.2), gridspec_kw={"width_ratios": [1.2, 1]})
    cs = [c for c in B["cases"] if c.get("retrieval")]
    ranks = [c["retrieval"]["firstPrimaryRank"] or 0 for c in cs]
    bars = a1.bar([c["case"] for c in cs], [(r if r else 6) for r in ranks])
    for bar, r in zip(bars, ranks):
        if not r: bar.set_hatch("//"); bar.set_alpha(0.5)
    a1.bar_label(bars, labels=[str(r) if r else "miss" for r in ranks], fontsize=8, padding=2)
    a1.set_ylabel("Rank of the first PRIMARY runbook (1 = best)"); a1.set_ylim(0, 7.5); a1.set_title("Retrieval: first primary runbook (miss = not in top 5)")
    labs = ["Compliant\n(evaluated)", "No valid\nrecommendation", "Workflow\ncompleted"]
    av = [A["compliance"]["compliant"], len(A["noValidRecommendation"]), A["workflowCompleted"]["n"]]; bv = [B["compliance"]["compliant"], len(B["noValidRecommendation"]), B["workflowCompleted"]["n"]]
    x = range(3); w = 0.38
    r1 = a2.bar([i - w / 2 for i in x], av, w, label="A: empty corpus"); r2 = a2.bar([i + w / 2 for i in x], bv, w, label="B: 17 runbooks")
    a2.bar_label(r1, fontsize=8, padding=2); a2.bar_label(r2, fontsize=8, padding=2)
    a2.set_xticks(list(x)); a2.set_xticklabels(labs, fontsize=8); a2.set_ylabel("Cases (of 9 attempted)"); a2.set_ylim(0, 11)
    a2.set_title("Same pipeline, one run per case per arm"); a2.legend(frameon=False, loc="upper right")
    save(fig, "figure3_rag")

# 4 — IP-order diagnostic
if order:
    fig, ax = plt.subplots(figsize=(7, 4)); cats = ["destination (correct)", "source (wrong)", "no destination-IP step"]
    names = [f"{r['incidentId'][:8]}\n{r['variant']}" for r in order["results"]]
    bottoms = [0] * len(order["results"])
    for cat in cats:
        vals = [sum(1 for p in r["picks"] if p["role"] == cat) for r in order["results"]]
        ax.bar(range(len(names)), vals, bottom=bottoms, label=cat); bottoms = [b + v for b, v in zip(bottoms, vals)]
    ax.set_xticks(range(len(names))); ax.set_xticklabels(names, fontsize=8); ax.set_ylabel("Runs (5 per bar)"); ax.set_ylim(0, 6.5)
    ax.set_title("First destination-IP step vs the order of IP candidates in the context"); ax.legend(frameon=False, fontsize=8, loc="upper center", ncol=3)
    save(fig, "figure4_ip_order_diagnostic")
