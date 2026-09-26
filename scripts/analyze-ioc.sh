#!/usr/bin/env bash
# Sends a single IOC (IPv4/IPv6/domain/URL/email/MD5/SHA1/SHA256) to the
# Threat Intelligence module's POST /api/threat-intelligence/analyze — the
# same endpoint the "Analyze a single IOC" panel on the Threat Intelligence
# dashboard page calls. No signature/auth needed (unlike the SIEM webhook —
# this route is currently unauthenticated, matching main.ts's own routing).
#
# Usage:
#   ./scripts/analyze-ioc.sh 185.220.101.1
#   ./scripts/analyze-ioc.sh evil.example.com
#   BACKEND_URL=http://localhost:11749 ./scripts/analyze-ioc.sh 8.8.8.8   # override port
set -euo pipefail

IOC="${1:-}"
if [ -z "$IOC" ]; then
  echo "Usage: $0 <ioc>   (IPv4, IPv6, domain, URL, email, MD5, SHA1, or SHA256)" >&2
  exit 1
fi

BACKEND_URL="${BACKEND_URL:-http://localhost:4000}"

BODY="$(printf '{"ioc":"%s"}' "$IOC")"

echo "-> Analyzing $IOC via $BACKEND_URL/api/threat-intelligence/analyze"
RESPONSE="$(curl -sS -X POST "$BACKEND_URL/api/threat-intelligence/analyze" \
  -H "Content-Type: application/json" \
  --data-binary "$BODY")"

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
