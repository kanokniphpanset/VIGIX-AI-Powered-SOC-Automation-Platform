#!/usr/bin/env bash
# Real SSH brute force from vigix-lab-attacker against vigix-lab-agent (lab containers only).
# Wrong passwords for a non-existent and an existing user -> sshd "Failed password" lines -> Wazuh rules
# 5710 / 5760 and the brute-force rules 5712 / 5763 (level 10) -> VIGIX Alert Inbox.
#   bash infra/wazuh-lab/attack-ssh-bruteforce.sh [attempts]
set -euo pipefail
ATTEMPTS="${1:-12}"
TARGET="vigix-lab-agent"

for user in admin labuser; do
  echo "Trying ${ATTEMPTS} wrong passwords for '${user}'@${TARGET}..."
  docker exec vigix-lab-attacker sh -c "for i in \$(seq 1 ${ATTEMPTS}); do sshpass -p wrong\$i ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o ConnectTimeout=5 ${user}@${TARGET} true 2>/dev/null; done; true"
done

echo "Done. Wazuh needs a few seconds; then check:"
echo "  docker exec single-node-wazuh.manager-1 tail -5 /var/ossec/logs/integrations.log"
echo "  VIGIX Alert Inbox: http://localhost:5173/alerts"
