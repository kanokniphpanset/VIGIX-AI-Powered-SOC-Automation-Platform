#!/usr/bin/env bash
# Send one (or all) TC-*.json alert(s) to the VIGIX webhook, signed with the
# same HMAC-SHA256 scheme webhookAuth.middleware.ts checks
# (X-Webhook-Signature: sha256=<hex> over the exact raw body). Reads
# SIEM_WEBHOOK_SECRET from apps/backend/.env, same as scripts/send-test-alert.sh.
#
# Usage:
#   ./send-tc.sh                              # send every TC-*.json in this folder
#   ./send-tc.sh TC-05-powershell.json        # send just one
#   BACKEND_URL=http://localhost:4000 DELAY=3 ./send-tc.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKEND_ENV="$REPO_ROOT/apps/backend/.env"
BACKEND_URL="${BACKEND_URL:-http://localhost:4000}"

if [ -z "${SIEM_WEBHOOK_SECRET:-}" ] && [ -f "$BACKEND_ENV" ]; then
  SIEM_WEBHOOK_SECRET="$(grep -E '^SIEM_WEBHOOK_SECRET=' "$BACKEND_ENV" | head -n1 | cut -d'=' -f2- | tr -d '"')"
fi
if [ -z "${SIEM_WEBHOOK_SECRET:-}" ]; then
  echo "SIEM_WEBHOOK_SECRET not set and not found in $BACKEND_ENV" >&2
  exit 1
fi

send_one() {
  local f="$1"
  [ -f "$f" ] || { echo "no such file: $f" >&2; return 1; }
  local sig
  sig="$(openssl dgst -sha256 -hmac "$SIEM_WEBHOOK_SECRET" -r "$f" | awk '{print $1}')"
  echo "-> POST $(basename "$f")"
  curl -sS -X POST "$BACKEND_URL/api/v1/webhooks/siem/wazuh" \
    -H "Content-Type: application/json" \
    -H "X-Webhook-Signature: sha256=$sig" \
    --data-binary @"$f"
  echo
  sleep "${DELAY:-2}"
}

if [ $# -ge 1 ]; then
  send_one "$SCRIPT_DIR/$1"
else
  for f in "$SCRIPT_DIR"/TC-*.json; do send_one "$f"; done
fi
