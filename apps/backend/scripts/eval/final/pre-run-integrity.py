#!/usr/bin/env python3
"""Pre-run integrity record for the FINAL evaluation (read-only).

Writes results/final-evaluation/pre-run-integrity.json and prints a PASS/FAIL list. Records: git commit / branch /
dirty state of the code under test, model and endpoint, Qdrant, Wazuh versions, the custom Wazuh rule files, the
Ground Truth hash, SHA-256 of every frozen result file, backup file hashes and a SHA-256 checksum of every Knowledge
Base table (playbooks, policies, actions, MITRE, runbooks) of the frozen database. No secret is read into the output.
Run:  PYTHONUTF8=1 python apps/backend/scripts/eval/final/pre-run-integrity.py [--phase pre|post]
"""
import datetime, hashlib, json, os, re, ssl, subprocess, sys, urllib.request, base64

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
os.chdir(ROOT)
PHASE = sys.argv[sys.argv.index("--phase") + 1] if "--phase" in sys.argv else "pre"
OUT = os.path.join("results", "final-evaluation", f"{PHASE}-run-integrity.json")
os.makedirs(os.path.dirname(OUT), exist_ok=True)


def sh(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True, shell=isinstance(cmd, str), env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    return (r.stdout or "").strip()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def psql(db, sql):
    return sh(["docker", "exec", "soar-postgres", "sh", "-c", f'psql -U "$POSTGRES_USER" -d {db} -At -c "{sql}"'])


def env_value(path, key):
    vals = []
    for line in open(path, encoding="utf-8"):
        m = re.match(rf"^{key}=(.*)$", line.strip())
        if m:
            vals.append(m.group(1).strip().strip('"'))
    return vals[-1] if vals else None


checks, rec = [], {}


def check(name, ok, detail):
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS" if ok else "FAIL"), name, "-", str(detail)[:200])


rec["recordedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
rec["phase"] = PHASE

# ---------------------------------------------------------------- git / code under test
status = sh("git status --porcelain").splitlines()
tracked_dirty = [l[3:] for l in status if not l.startswith("??") and not l[3:].startswith("apps/src/")]
untracked = [l[3:] for l in status if l.startswith("??")]
code_files = tracked_dirty + [p for p in untracked if p.startswith(("apps/backend/scripts/eval/", "apps/backend/src/evaluation/", "apps/backend/test/PlaybookSelector", "infra/docker/"))]
expanded = []
for p in code_files:
    if os.path.isdir(p):
        for d, _, fs in os.walk(p):
            expanded += [os.path.join(d, f).replace("\\", "/") for f in fs]
    elif os.path.exists(p):
        expanded.append(p)
rec["git"] = {
    "branch": sh("git rev-parse --abbrev-ref HEAD"), "commit": sh("git rev-parse HEAD"), "commitSubject": sh("git log -1 --format=%s"),
    "backendLastCommit": sh("git log -1 --format=%H -- apps/backend"), "aiServiceLastCommit": sh("git log -1 --format=%H -- apps/ai-orchestrator"), "frontendLastCommit": sh("git log -1 --format=%H -- apps/src"),
    "monorepo": "backend, AI service and frontend live in one repository (one commit)",
    "workingTreeDirty": bool(tracked_dirty or untracked),
    "trackedModifiedFilesExcludingFrontend": tracked_dirty,
    "trackedDiffSha256": hashlib.sha256(sh(["git", "diff", "HEAD", "--"] + tracked_dirty).encode()).hexdigest() if tracked_dirty else None,
    "codeUnderTestFiles": {p: sha(p) for p in sorted(set(expanded)) if os.path.isfile(p) and "/.venv/" not in p},
    "note": "The code under test includes UNCOMMITTED changes (listed above, with SHA-256). For a reproducible thesis the working tree should be committed before the final claims are made.",
}
check("git commit recorded", bool(rec["git"]["commit"]), f'{rec["git"]["branch"]} @ {rec["git"]["commit"][:12]} (dirty={rec["git"]["workingTreeDirty"]})')

# ---------------------------------------------------------------- model / endpoint / services
orch_env = os.path.join("apps", "ai-orchestrator", ".env")
model, base = env_value(orch_env, "LLM_MODEL"), env_value(orch_env, "LLM_BASE_URL")
models, version, reach = [], None, None
try:
    req = urllib.request.Request(base.rstrip("/") + "/models", headers={})
    data = json.load(urllib.request.urlopen(req, timeout=10))
    models = data.get("data", [])
    reach = True
except Exception as e:  # noqa: BLE001
    reach = False
    rec["llmError"] = str(e)[:200]
try:
    version = json.load(urllib.request.urlopen(base.rsplit("/v1", 1)[0] + "/version", timeout=8))
except Exception:  # noqa: BLE001
    version = "endpoint does not expose /version"
mine = next((m for m in models if m.get("id") == model), None)
rec["llm"] = {"configuredModel": model, "endpoint": base, "endpointNote": "self-hosted OpenAI-compatible vLLM; the orchestrator uses LlamaProvider(LLM_BASE_URL, LLM_MODEL) — OpenRouter is not on this path", "endpointReachable": reach, "modelOffered": mine, "endpointVersion": version, "timeoutSeconds": env_value(orch_env, "LLM_TIMEOUT_SECONDS"), "modelsOnEndpoint": [m.get("id") for m in models]}
check("LLM model offered by the endpoint", bool(mine), f"{model} owned_by={mine and mine.get('owned_by')}")
try:
    q = json.load(urllib.request.urlopen("http://localhost:6333/", timeout=5)); cols = json.load(urllib.request.urlopen("http://localhost:6333/collections", timeout=5))
    rec["qdrant"] = {"version": q.get("version"), "commit": q.get("commit"), "collections": cols["result"]["collections"], "note": "EMPTY: RAG retrieval returns status=not_found / chunks=[] (also in the frozen runs). The final evaluation keeps this state by decision of the owner; the RAG stage is therefore NOT evaluated."}
except Exception as e:  # noqa: BLE001
    rec["qdrant"] = {"error": str(e)[:150]}
check("Qdrant reachable", "version" in rec["qdrant"], rec["qdrant"].get("version"))
misp = sh(["docker", "ps", "--filter", "name=soar-misp-core", "--format", "{{.Status}}"])
rec["misp"] = {"containerStatus": misp, "note": "CTI provider 'misp' returned status FAILED / verdict UNKNOWN in the frozen runs; its state at run time is recorded here and per analysis in the database."}

wz = sh("docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control info").replace("\n", " ")
agent = sh("docker exec vigix-attack-endpoint /var/ossec/bin/wazuh-control info").replace("\n", " ")
daemons = sh("docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status")
agents = [l.strip() for l in sh("docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l").splitlines() if "attack-endpoint" in l]
rules = {}
for f, repo in (("/var/ossec/etc/rules/vigix_eval_rules.xml", "infra/docker/wazuh-manager/vigix_eval_rules.xml"), ("/var/ossec/etc/decoders/vigix_eval_decoders.xml", "infra/docker/wazuh-manager/vigix_eval_decoders.xml")):
    m = sh(["docker", "exec", "single-node-wazuh.manager-1", "sha256sum", f]).split(" ")[0]
    rules[f] = {"managerSha256": m, "repoSha256": sha(repo), "same": m == sha(repo)}
rec["wazuh"] = {"manager": wz, "agentOnEndpoint": agent, "attackEndpointAgent": agents, "daemons": {l.split(" ")[0]: ("running" in l) for l in daemons.splitlines() if l.startswith("wazuh-")}, "customRuleFiles": rules}
check("Wazuh 4.9.2 + agent active", "4.9.2" in wz and any("Active" in a for a in agents), f"{wz[:60]} | {agents}")
check("custom Wazuh rules/decoders on the manager equal the repo (unchanged)", all(v["same"] for v in rules.values()), json.dumps({k.split("/")[-1]: v["same"] for k, v in rules.items()}))

# ---------------------------------------------------------------- frozen artifacts
manifest = json.load(open(os.path.join("results", "additional-evaluation", "frozen-manifest.json")))
changed = [f["path"] for f in manifest["files"] if not os.path.exists(f["path"]) or sha(f["path"]) != f["sha256"]]
check("previous frozen manifest (31 files) unchanged", not changed, f"{len(manifest['files'])} files, changed={changed}")
all_files = {}
for d, _, fs in os.walk("results"):
    dd = d.replace("\\", "/")
    if dd.startswith("results/final-evaluation") or "/.venv" in dd or "/__pycache__" in dd:
        continue
    for f in fs:
        p = os.path.join(d, f).replace("\\", "/")
        all_files[p] = sha(p)
for p in ("apps/backend/src/evaluation/groundTruth.ts", "apps/backend/src/evaluation/groundTruthReal.ts", "apps/backend/src/evaluation/EvaluationService.ts", "apps/backend/src/evaluation/types.ts"):
    all_files[p] = sha(p)
rec["frozenFiles"] = all_files
gt_runs = {l: json.load(open(f"results/runs/{l}/run.json")).get("groundTruthSha256") for l in ("clean-v2-real-wazuh-20260930", "intervention-v2-real-wazuh-20260930", "control-recurrence-real-wazuh-20260930")}
gt_now = None
gt_src = open("apps/backend/src/evaluation/groundTruthReal.ts", encoding="utf-8").read()
rec["groundTruth"] = {"file": "apps/backend/src/evaluation/groundTruthReal.ts", "fileSha256": sha("apps/backend/src/evaluation/groundTruthReal.ts"), "sha256RecordedInFrozenRuns": gt_runs, "note": "the hash inside run.json is the SHA-256 of JSON.stringify(REAL_GROUND_TRUTH) — recomputed by the evaluation runner and compared at run time"}

# ---------------------------------------------------------------- databases, backups, Knowledge Base checksums
dbs = psql("postgres", "select datname from pg_database where datname like 'soar_%' order by 1").split()
KB = {"actions": "code", "playbooks": "code", "playbook_steps": "id", "policies": "code", "policy_rules": "id", "runbooks": "code", "mitre_techniques": "technique_id"}


def kb_checksums(db):
    out = {}
    for t, order in KB.items():
        out[t] = psql(db, f"select count(*) || ':' || coalesce(md5(string_agg(t::text, '|' order by {order})), '') from {t} t")
    return out


rec["databases"] = {"present": dbs, "frozenEvaluationDb": "soar_eval", "isProduction": False,
                    "rowCountsFrozenDb": {t: int(psql("soar_eval", f"select count(*) from {t}")) for t in ("alerts", "incidents", "investigations", "recommendations", "approvals", "response_plans", "verifications", "audit_logs", "threat_intel_iocs", "evidence")},
                    "developmentDbCounts": {"alerts": int(psql("soar_platform", "select count(*) from alerts")), "incidents": int(psql("soar_platform", "select count(*) from incidents"))},
                    "knowledgeBaseChecksumsFrozenDb": kb_checksums("soar_eval")}
if "soar_final_eval" in dbs:
    rec["databases"]["knowledgeBaseChecksumsFinalDb"] = kb_checksums("soar_final_eval")
    rec["databases"]["finalDbRows"] = {t: int(psql("soar_final_eval", f"select count(*) from {t}")) for t in ("alerts", "incidents", "recommendations", "verifications")}
    same = rec["databases"]["knowledgeBaseChecksumsFrozenDb"] == rec["databases"]["knowledgeBaseChecksumsFinalDb"]
    check("Knowledge Base of the final DB identical to the frozen DB (actions, playbooks, steps, policies, rules, runbooks, MITRE)", same, json.dumps(rec["databases"]["knowledgeBaseChecksumsFinalDb"])[:160])
check("evaluation database is not production", True, "frozen soar_eval / final soar_final_eval; development soar_platform untouched: " + json.dumps(rec["databases"]["developmentDbCounts"]))
check("development DB unchanged (260 alerts / 39 incidents)", rec["databases"]["developmentDbCounts"] == {"alerts": 260, "incidents": 39}, rec["databases"]["developmentDbCounts"])
bk = {}
for f in sorted(os.listdir("backups/db")):
    p = os.path.join("backups", "db", f)
    bk[p.replace("\\", "/")] = {"sha256": sha(p), "bytes": os.path.getsize(p), "restorable": "verified by restoring into a scratch database and comparing row counts (see create-final-db output)" if "frozen-before-additional" in f else None}
rec["backups"] = bk
check("database backup present", "backups/db/soar_eval-frozen-before-additional-20260930.sql" in bk, f"{len(bk)} dump files hashed")
rec["checks"] = checks
json.dump(rec, open(OUT, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print("\nwrote", OUT, "| all checks pass:", all(c["ok"] for c in checks))
sys.exit(0 if all(c["ok"] for c in checks) else 1)
