#!/usr/bin/env bash
# eval-env.sh — process environment for the Real-Wazuh evaluation. SOURCE it (`. eval-env.sh`) or run it with
# `start-orchestrator` to launch a SECOND AI orchestrator bound to the evaluation database.
#
# Nothing here is written to any .env: values are derived from apps/backend/.env at run time and only
# exported into THIS process, so the developer's normal backend / orchestrator / database are untouched.
#   - DATABASE_URL          -> the *_eval database (never soar_platform)
#   - AI_ORCHESTRATOR_URL   -> the second orchestrator on :8001 (it must read/write the same eval DB)
#   - RECOMMENDATION_AGENT  -> llm   (apps/backend/.env has "fake"; evaluation must use the real LLM path)
#   - REHUNT_PROVIDER       -> wazuh (REAL_WAZUH verification; never mock)
set -eu
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BE_ENV="$ROOT/apps/backend/.env"
EVAL_DB="${EVAL_DB:-soar_eval}"
getv() { grep -E "^$1=" "$BE_ENV" | head -n1 | cut -d= -f2- | tr -d '"'; }

BASE_URL="$(getv DATABASE_URL)"
export DATABASE_URL="${BASE_URL%/*}/${EVAL_DB}"
export AI_ORCHESTRATOR_URL="http://localhost:8001"
export RECOMMENDATION_AGENT="llm"
export REHUNT_PROVIDER="wazuh"
export AI_WORKER_ENABLED="false"
for k in WAZUH_INDEXER_URL WAZUH_INDEXER_USERNAME WAZUH_INDEXER_PASSWORD WAZUH_INDEXER_CA_PATH WAZUH_INDEXER_TLS_SERVERNAME WAZUH_INDEX_PATTERN WAZUH_REHUNT_TIMEOUT_MS WAZUH_API_URL WAZUH_API_USERNAME WAZUH_API_PASSWORD WAZUH_API_CA_PATH QDRANT_URL; do
  v="$(getv "$k")"; [ -n "$v" ] && export "$k=$v"
done
export WAZUH_INDEXER_INSECURE_TLS="false"

if [ "${1:-}" = "start-orchestrator" ]; then
  # orchestrator-side names for the same indexer settings
  export WAZUH_INDEXER_USER="$(getv WAZUH_INDEXER_USERNAME)"
  export WAZUH_INDEXER_HOST="localhost" WAZUH_INDEXER_PORT="9200"
  WIN() { command -v cygpath >/dev/null 2>&1 && cygpath -w "$1" || echo "$1"; }
  export PYTHONPATH="$(WIN "$ROOT");$(WIN "$ROOT/apps/ai-orchestrator")"
  cd "$ROOT/apps/ai-orchestrator"
  echo "[eval-env] orchestrator :8001 -> DB ${EVAL_DB}"
  # same launcher as run_server.py (Windows selector event loop is required by psycopg), on port 8001
  exec .venv/Scripts/python.exe -c "import asyncio,sys,uvicorn; sys.platform=='win32' and asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()); uvicorn.run('src.main:app', host='127.0.0.1', port=8001, loop='asyncio')"
fi
