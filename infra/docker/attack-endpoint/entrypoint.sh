#!/usr/bin/env bash
# Boot the endpoint: start real services, then enroll + start the Wazuh agent.
set -u

MANAGER="${WAZUH_MANAGER:-single-node-wazuh.manager-1}"

echo "[endpoint] starting rsyslog (writes /var/log/auth.log + /var/log/syslog)..."
# Clear any stale /dev/log + pidfile from the image layer so imuxsock can
# create a fresh socket (rsyslog config already has imklog disabled + imuxsock
# pinned to /dev/log — see Dockerfile). rsyslog ships no SysV init here.
rm -f /dev/log /var/run/rsyslogd.pid 2>/dev/null || true
# Run in the FOREGROUND (-n) backgrounded by the shell. Self-daemonizing
# rsyslogd double-forks and, with pid 1 being `tail` (not an init that reaps),
# the daemon ends up a defunct zombie with /dev/log left unlistened (verified:
# State: Z, no listener on the socket). Foreground mode stays a live listener.
rsyslogd -n &
sleep 2
# Create the log files owned by syslog:adm so rsyslog (which drops privileges
# to the 'syslog' user) can actually write them — creating them as root makes
# rsyslog's omfile action suspend with a silent permission error and auth.log
# stays empty (verified). The agent runs as root and can still read them.
install -o syslog -g adm -m 640 /dev/null /var/log/auth.log 2>/dev/null || : > /var/log/auth.log
install -o syslog -g adm -m 640 /dev/null /var/log/syslog  2>/dev/null || : > /var/log/syslog

echo "[endpoint] starting sshd, nginx, auditd..."
# auditd needs the host to allow it; if the kernel audit socket is unavailable
# (common in containers) we continue anyway — the other event sources still work.
service ssh start || echo "[endpoint] ssh start warning"
service nginx start || echo "[endpoint] nginx start warning"
service auditd start 2>/dev/null || echo "[endpoint] auditd unavailable in container (non-fatal)"

# --- enroll the agent with the manager (authd on 1515) -----------------------
# Idempotent: if client.keys already has a key we skip registration.
if ! grep -q . /var/ossec/etc/client.keys 2>/dev/null; then
  echo "[endpoint] registering agent with manager ${MANAGER} ..."
  # password-less authd is the single-node default; -A gives a stable agent name
  /var/ossec/bin/agent-auth -m "${MANAGER}" -A "attack-endpoint" || {
    echo "[endpoint] agent-auth failed; will retry via agent auto-enrollment"; }
fi

echo "[endpoint] starting wazuh-agent..."
/var/ossec/bin/wazuh-control start

echo "[endpoint] ready. Manager=${MANAGER}"
echo "[endpoint] agent status:"
/var/ossec/bin/wazuh-control status || true

# keep the container alive and stream agent log for visibility
touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
