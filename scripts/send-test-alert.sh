#!/usr/bin/env bash
# Sends one randomized Wazuh-shaped alert to the local backend webhook,
# signed with the same HMAC-SHA256 scheme webhookAuth.middleware.ts checks
# (see README.md "Send a test alert through the full pipeline"). Reads
# SIEM_WEBHOOK_SECRET straight out of apps/backend/.env so it never goes
# stale if that secret is rotated.
#
# Usage:
#   ./scripts/send-test-alert.sh
#   BACKEND_URL=http://localhost:11749 ./scripts/send-test-alert.sh   # override port
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_ENV="$REPO_ROOT/apps/backend/.env"

BACKEND_URL="${BACKEND_URL:-http://localhost:4000}"

if [ -z "${SIEM_WEBHOOK_SECRET:-}" ] && [ -f "$BACKEND_ENV" ]; then
  SIEM_WEBHOOK_SECRET="$(grep -E '^SIEM_WEBHOOK_SECRET=' "$BACKEND_ENV" | head -n1 | cut -d'=' -f2- | tr -d '"')"
fi
if [ -z "${SIEM_WEBHOOK_SECRET:-}" ]; then
  echo "SIEM_WEBHOOK_SECRET not set and not found in $BACKEND_ENV" >&2
  exit 1
fi

A=$((RANDOM % 5))
if   [ "$A" -eq 0 ]; then R='5712|10|T1110|Credential Access|Brute Force|sshd'
elif [ "$A" -eq 1 ]; then R='5716|7|T1046|Discovery|Network Service Scanning|iptables'
elif [ "$A" -eq 2 ]; then R='554|12|T1204|Execution|User Execution|syscheck'
elif [ "$A" -eq 3 ]; then R='91816|12|T1059.001|Execution|PowerShell|windows_eventchannel'
else                      R='31103|10|T1190|Initial Access|Exploit Public-Facing Application|web-accesslog'
fi
IFS='|' read -r RULE LEVEL MITRE TACTIC TECHNIQUE DECODER <<< "$R"
IP="185.220.101.$((RANDOM % 200 + 1))"

BODY="{\"id\":\"$(date +%s).$((RANDOM % 9000 + 1000))\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)\",\"manager\":{\"name\":\"wazuh-manager\"},\"agent\":{\"id\":\"001\",\"name\":\"linux-server-01\",\"ip\":\"192.168.1.10\"},\"rule\":{\"id\":\"$RULE\",\"level\":$LEVEL,\"description\":\"$TECHNIQUE detected\",\"groups\":[\"security\"],\"firedtimes\":$((RANDOM % 10 + 1)),\"mail\":false,\"mitre\":{\"id\":[\"$MITRE\"],\"tactic\":[\"$TACTIC\"],\"technique\":[\"$TECHNIQUE\"]}},\"decoder\":{\"name\":\"$DECODER\",\"parent\":\"$DECODER\"},\"location\":\"/var/log/auth.log\",\"srcip\":\"$IP\",\"srcport\":\"49231\",\"srcuser\":\"unknown\",\"dstip\":\"192.168.1.10\",\"dstport\":\"22\",\"dstuser\":\"root\",\"protocol\":\"tcp\",\"action\":\"attack_detected\",\"user\":\"root\",\"authentication_method\":\"ssh\",\"status\":\"failed\",\"process\":{\"name\":\"$DECODER\",\"pid\":1234,\"command_line\":\"$TECHNIQUE detected\",\"parent\":\"systemd\"},\"file\":{},\"data\":{\"attack_type\":\"$TECHNIQUE\",\"srcip\":\"$IP\",\"test\":true},\"full_log\":\"$TECHNIQUE detected from $IP\",\"custom_test_field\":{\"scenario\":\"random_attack\",\"generated\":true}}"

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT
printf '%s' "$BODY" > "$TMP_FILE"

SIG="$(openssl dgst -sha256 -hmac "$SIEM_WEBHOOK_SECRET" -r "$TMP_FILE" | awk '{print $1}')"

echo "-> $TECHNIQUE ($MITRE) from $IP, level $LEVEL"
curl -sS -X POST "$BACKEND_URL/api/v1/webhooks/siem/wazuh" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=$SIG" \
  --data-binary @"$TMP_FILE"
echo
