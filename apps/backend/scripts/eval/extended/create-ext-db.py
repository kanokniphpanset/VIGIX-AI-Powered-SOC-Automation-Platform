#!/usr/bin/env python3
"""Create the FINAL evaluation database `soar_ext_eval` from the verified backup of the frozen evaluation database.

1. restore backups/db/soar_eval-frozen-before-additional-20260930.sql into a NEW database and compare its row counts with
   the frozen manifest (this is the backup-restorability check);
2. truncate workflow data with reset-final-db.sql (Knowledge Base kept; its guard refuses any other database name);
3. record the Knowledge Base checksums of the result vs the frozen database.
Nothing touches soar_eval or soar_platform.  Run: PYTHONUTF8=1 python apps/backend/scripts/eval/final/create-final-db.py
"""
import json, os, subprocess, datetime
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
os.chdir(ROOT)
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}
DUMP = "backups/db/soar_eval-frozen-before-additional-20260930.sql"
DB = "soar_ext_eval"


def psql(db, sql, stdin=None):
    return subprocess.run(["docker", "exec", "-i", "soar-postgres", "sh", "-c", f'psql -U "$POSTGRES_USER" -d {db} -At -v ON_ERROR_STOP=1 -q' + ("" if stdin else f' -c "{sql}"')], input=stdin, capture_output=True, text=True, env=ENV)


assert DB.endswith("_eval") and DB != "soar_eval" and DB != "soar_platform"
print(psql("postgres", f"DROP DATABASE IF EXISTS {DB}").stderr.strip())
r = psql("postgres", f"CREATE DATABASE {DB}"); assert r.returncode == 0, r.stderr
r = psql(DB, "", stdin=open(DUMP, encoding="utf-8").read()); errs = [l for l in r.stderr.splitlines() if l.startswith("ERROR")]
manifest = json.load(open("results/additional-evaluation/frozen-manifest.json"))["soar_eval"]
restored = {t: int(psql(DB, f"select count(*) from {t}").stdout.strip()) for t in manifest}
ok = restored == manifest
print("restore errors:", len(errs), "| row counts equal to the frozen manifest:", ok)
rst = psql(DB, "", stdin=open("apps/backend/scripts/eval/extended/reset-ext-db.sql", encoding="utf-8").read())
print(rst.stdout.strip()[-600:], rst.stderr.strip()[-300:])
after = {t: int(psql(DB, f"select count(*) from {t}").stdout.strip()) for t in ("alerts", "incidents", "recommendations", "verifications", "audit_logs", "actions", "playbooks", "policies", "mitre_techniques", "runbooks")}
json.dump({"createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "database": DB, "restoredFrom": DUMP, "restoreErrors": len(errs), "rowCountsAfterRestoreEqualFrozenManifest": ok, "rowCountsAfterRestore": restored, "rowCountsAfterReset": after}, open("results/extended-evaluation/ext-db-creation.json", "w"), indent=2)
print("after reset:", after)
raise SystemExit(0 if ok and not errs else 1)
