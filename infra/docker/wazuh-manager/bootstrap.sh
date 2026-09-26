#!/usr/bin/env bash
# One-time setup for the wazuh-manager service in docker-compose.yml.
#
# Why this exists instead of a plain `docker compose up`: the official
# wazuh/wazuh-manager image populates /var/ossec/etc/ (ossec.conf plus
# ~10 sibling files: ar.conf, client.keys, decoder/rule dirs, etc.) via its
# own entrypoint init script on first boot into whatever volume is mounted
# there — bind-mounting a single custom ossec.conf directly into that path
# skips that init step for the REST of /var/ossec/etc, and the manager
# fails to start ("Configuration error... Could not open file
# 'etc/shared/ar.conf'" — verified directly, not assumed). The reliable
# sequence, verified end-to-end against a real Wazuh alert reaching the
# real backend webhook and landing in real Postgres:
#   1. Let the container boot ONCE into a fresh named volume with the
#      image's own defaults (populates every sibling file ossec.conf needs).
#   2. Stop it, `docker cp` our customized ossec.conf + the custom-vigix
#      integration scripts into that now-populated volume.
#   3. Start it again — every required sibling file is still there, plus
#      our customizations.
#
# Run this once after `docker compose up -d wazuh-manager` creates the
# service for the first time. Re-running is safe (idempotent) but
# unnecessary once the named volume already has the custom files.
#
# Re-run needed whenever the wazuh_manager_integrations volume is fresh —
# verified this happens on any `docker compose up` that changes a
# non-volume field on this service (recreates the container); the custom
# scripts themselves now live in a named volume (wazuh_manager_integrations)
# so a plain `docker restart` never loses them, only a volume-losing
# recreate does.
set -euo pipefail
# Prevents Git Bash on Windows from rewriting container-side absolute Unix
# paths (e.g. /var/ossec/etc/ossec.conf) into host Windows paths before
# they reach `docker exec`/`docker run` — verified: without this, chmod/
# chown calls below fail with "cannot access 'C:/Program Files/Git/var/...'".
# NOTE: this also means the LOCAL (host-side) source paths passed to
# `docker cp` below must be pre-converted with `cygpath -w` — with
# MSYS_NO_PATHCONV=1 set, Docker Desktop's native docker.exe cannot resolve
# an MSYS-style /d/... source path either. Verified both ways fail if not
# handled exactly like this (destination stays raw Unix, source gets
# cygpath'd).
export MSYS_NO_PATHCONV=1

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER_NAME="soar-wazuh-manager"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_SRC="$(cd "$SELF_DIR/../../wazuh-integration" && pwd)"
BACKEND_ENV="$(cd "$SELF_DIR/../../../apps/backend" && pwd)/.env"

echo "Waiting for $CONTAINER_NAME to complete its first-boot default install..."
for i in $(seq 1 30); do
  if docker exec "$CONTAINER_NAME" test -f /var/ossec/etc/internal_options.conf 2>/dev/null; then
    break
  fi
  sleep 2
done

echo "Stopping $CONTAINER_NAME to patch in customized config..."
docker stop "$CONTAINER_NAME"

# ossec.conf's tracked <api_key> is a __SIEM_WEBHOOK_SECRET__ placeholder —
# never the live secret (see ossec.conf's own comment). Substitute the real
# value from apps/backend/.env into a throwaway temp copy before cp'ing, so
# custom-vigix.py can sign requests the same way webhookAuth.middleware.ts
# verifies them. Missing/unset backend secret degrades to an empty
# <api_key> — custom-vigix.py already treats that as "send unsigned",
# matching the middleware's own behavior when SIEM_WEBHOOK_SECRET is unset.
SIEM_WEBHOOK_SECRET="$(grep -m1 '^SIEM_WEBHOOK_SECRET=' "$BACKEND_ENV" 2>/dev/null | cut -d= -f2- | tr -d '"')"
TMP_OSSEC_CONF="$(mktemp)"
sed "s/__SIEM_WEBHOOK_SECRET__/${SIEM_WEBHOOK_SECRET}/" "$SELF_DIR/ossec.conf" > "$TMP_OSSEC_CONF"

docker cp "$(cygpath -w "$TMP_OSSEC_CONF")" "$CONTAINER_NAME:/var/ossec/etc/ossec.conf"
docker cp "$(cygpath -w "$INTEGRATION_SRC/custom-vigix")" "$CONTAINER_NAME:/var/ossec/integrations/custom-vigix"
docker cp "$(cygpath -w "$INTEGRATION_SRC/custom-vigix.py")" "$CONTAINER_NAME:/var/ossec/integrations/custom-vigix.py"
rm -f "$TMP_OSSEC_CONF"

echo "Starting $CONTAINER_NAME..."
docker start "$CONTAINER_NAME"

echo "Waiting for daemons to come up..."
sleep 8
docker exec "$CONTAINER_NAME" chmod 750 /var/ossec/integrations/custom-vigix /var/ossec/integrations/custom-vigix.py
docker exec "$CONTAINER_NAME" chown root:wazuh /var/ossec/integrations/custom-vigix /var/ossec/integrations/custom-vigix.py
docker restart "$CONTAINER_NAME"
sleep 8

echo "=== Verifying wazuh-integratord accepted custom-vigix ==="
docker logs --since 15s "$CONTAINER_NAME" 2>&1 | grep -iE "integratord|custom-vigix" || true
echo ""
echo "Bootstrap complete. Test with:"
echo "  docker exec $CONTAINER_NAME bash -c 'echo \"Aug 21 12:00:01 workstation-01 sshd[1]: Failed password for invalid user root from 10.10.10.50 port 51234 ssh2\" >> /var/log/auth.log'"
echo "  (repeat ~8x within a few seconds to cross the brute-force rule's threshold)"
echo "  docker logs $CONTAINER_NAME 2>&1 | grep custom-vigix   # or: docker exec $CONTAINER_NAME cat /var/ossec/logs/integrations.log"
