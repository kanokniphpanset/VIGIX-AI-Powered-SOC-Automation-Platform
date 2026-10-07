#!/usr/bin/env bash
# One-command driver for the VIGIX attack endpoint.
#
#   ./run.sh up          build image + start endpoint, enroll to the manager
#   ./run.sh attack      run all 10 attacks on the endpoint
#   ./run.sh attack 3    run only attack N
#   ./run.sh verify      summarize the alerts this endpoint generated on the manager
#   ./run.sh down        remove the endpoint container (+ its manager agent record)
#
# Requires the single-node Wazuh stack to be running (manager/indexer/dashboard)
# and the VIGIX backend reachable at host.docker.internal:4000 (custom-vigix
# integration already installed on the manager, forwarding level >= 7).
set -u
export MSYS_NO_PATHCONV=1
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="vigix-attack-endpoint:4.9.2"
NAME="vigix-attack-endpoint"
NET="${WAZUH_NET:-single-node_default}"
MANAGER="${WAZUH_MANAGER:-single-node-wazuh.manager-1}"
MGR_CTR="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"

case "${1:-}" in
  up)
    # cygpath the build context on Windows/Git-Bash so docker.exe can resolve it
    BUILD_CTX="$DIR"; command -v cygpath >/dev/null 2>&1 && BUILD_CTX="$(cygpath -w "$DIR")"
    docker build -t "$IMAGE" "$BUILD_CTX"
    docker rm -f "$NAME" 2>/dev/null || true
    docker run -d --name "$NAME" --network "$NET" \
      --cap-add AUDIT_CONTROL --cap-add AUDIT_READ \
      -e WAZUH_MANAGER="$MANAGER" "$IMAGE"
    echo "Waiting for agent enrollment..."; sleep 18
    docker exec "$MGR_CTR" /var/ossec/bin/agent_control -l | grep -i "$NAME" \
      || echo "Agent not visible yet — give it a few more seconds."
    ;;
  attack)
    # pass attack number only if given; an empty arg would be read as "attack ''"
    if [ -n "${2:-}" ]; then
      docker exec -e DELAY="${DELAY:-7}" "$NAME" bash /opt/attacks/run-attacks.sh "$2"
    else
      docker exec -e DELAY="${DELAY:-7}" "$NAME" bash /opt/attacks/run-attacks.sh
    fi
    ;;
  verify)
    docker exec "$MGR_CTR" bash -c "grep -h 'attack-endpoint' /var/ossec/logs/alerts/alerts.json | python3 -c \"
import sys,json,collections
c=collections.Counter()
for line in sys.stdin:
  try: a=json.loads(line)
  except: continue
  r=a.get('rule',{}); d=r.get('description','')
  if any(k in d for k in ['CIS','Benchmark']): continue
  if int(r.get('level',0))>=7: c[(int(r['level']),r.get('id'),d[:52])]+=1
print('LVL  RULE   COUNT DESCRIPTION (level>=7 -> forwarded to VIGIX)')
for (lvl,rid,desc),n in sorted(c.items(),key=lambda x:-x[0][0]):
  print(f'{lvl:>3} {rid:>6} {n:>6}  {desc}')
\""
    ;;
  down)
    docker rm -f "$NAME" 2>/dev/null || true
    for id in $(docker exec "$MGR_CTR" /var/ossec/bin/agent_control -l 2>/dev/null \
                 | grep 'attack-endpoint' | sed -E 's/.*ID: ([0-9]+),.*/\1/'); do
      docker exec "$MGR_CTR" /var/ossec/bin/manage_agents -r "$id" 2>/dev/null || true
    done
    echo "Removed endpoint + manager agent records."
    ;;
  *)
    grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//' | head -12 ;;
esac
