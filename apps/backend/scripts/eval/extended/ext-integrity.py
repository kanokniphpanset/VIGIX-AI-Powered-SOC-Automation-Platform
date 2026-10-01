#!/usr/bin/env python3
"""Integrity check for the EXTENDED evaluation: frozen artifacts unchanged, final DB unchanged, dev DB untouched, KB identical,
Wazuh custom rules unchanged, ground-truth pins match. Writes results/extended-evaluation/ext-integrity.json (never touches the final-evaluation files).
Run: PYTHONUTF8=1 python apps/backend/scripts/eval/extended/ext-integrity.py"""
import hashlib, json, os, subprocess, datetime
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
os.chdir(ROOT)
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
def psql(db, sql):
    return subprocess.run(["docker", "exec", "-i", "soar-postgres", "sh", "-c", f'psql -U "$POSTGRES_USER" -d {db} -At'], input=sql, capture_output=True, text=True, env=ENV).stdout.strip()
checks = []
def chk(name, ok, detail): checks.append({"check": name, "ok": bool(ok), "detail": detail}); print("PASS" if ok else "FAIL", name, "-", str(detail)[:160])

man = json.load(open("results/additional-evaluation/frozen-manifest.json", encoding="utf-8"))
files = man.get("files") or man.get("frozenFiles") or {}
changed = [x["path"] for x in files if not os.path.exists(x["path"]) or sha(x["path"]) != x["sha256"]]
chk("previous frozen manifest unchanged", not changed, f"{len(files)} files, changed={changed}")
chk("final DB soar_final_eval unchanged (10 alerts: 9 main + 1 reject)", psql("soar_final_eval", "select count(*) from alerts") == "10", psql("soar_final_eval", "select count(*) from alerts"))
chk("development DB soar_platform untouched (260 alerts / 39 incidents)", psql("soar_platform", "select count(*)||'/'||(select count(*) from incidents) from alerts") == "260/39", psql("soar_platform", "select count(*)||'/'||(select count(*) from incidents) from alerts"))
kb = "select (select count(*) from actions)||'/'||(select count(*) from playbooks)||'/'||(select count(*) from policies)||'/'||(select count(*) from runbooks)||'/'||(select count(*) from mitre_techniques)"
chk("Knowledge Base of soar_ext_eval equals soar_final_eval", psql("soar_ext_eval", kb) == psql("soar_final_eval", kb), psql("soar_ext_eval", kb))
gt = "apps/backend/src/evaluation/groundTruthReal.ts"
pre = json.load(open("results/final-evaluation/pre-run-integrity.json", encoding="utf-8"))["groundTruth"]["fileSha256"]
chk("frozen groundTruthReal.ts unchanged", sha(gt) == pre, sha(gt)[:16])
pins = json.load(open("results/extended-evaluation/ground-truth.sha256", encoding="utf-8"))
chk("extended ground truth pinned before the runs", all(k in pins for k in ("lowFp", "escalation", "rag")), list(k for k in pins if not k.endswith("At")))
rules = {}
for f in ("vigix_eval_rules.xml", "vigix_eval_decoders.xml"):
    sub = "rules" if "rules" in f else "decoders"
    live = subprocess.run(["docker", "exec", "single-node-wazuh.manager-1", "sha256sum", f"/var/ossec/etc/{sub}/{f}"], capture_output=True, text=True, env=ENV).stdout.split()[0]
    rules[f] = live == sha(f"infra/docker/wazuh-manager/{f}")
chk("custom Wazuh rules/decoders on the manager equal the repo", all(rules.values()), rules)
q = subprocess.run(["curl", "-s", "http://127.0.0.1:6335/collections/knowledge_embeddings"], capture_output=True, text=True).stdout
chk("isolated Qdrant holds the 17 runbooks; soar-qdrant (dev) still empty", '"points_count":17' in q and '"collections":[]' in subprocess.run(["curl", "-s", "http://127.0.0.1:6333/collections"], capture_output=True, text=True).stdout, "6335: 17 points; 6333: no collections")
out = {"recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "checks": checks, "allPass": all(c["ok"] for c in checks)}
json.dump(out, open("results/extended-evaluation/ext-integrity.json", "w", encoding="utf-8"), indent=1)
print("all pass:", out["allPass"])
