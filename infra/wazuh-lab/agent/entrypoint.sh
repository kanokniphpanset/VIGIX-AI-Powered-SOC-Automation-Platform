#!/bin/sh
# Start syslog + sshd, point the Wazuh agent at the manager, make sure it reads /var/log/auth.log, then run it.
set -e

CONF=/var/ossec/etc/ossec.conf
MANAGER="${WAZUH_MANAGER:-wazuh.manager}"

touch /var/log/auth.log
chown syslog:adm /var/log/auth.log 2>/dev/null || true
# No init system in a container: start the daemons directly (rsyslogd forks into the background).
# imklog needs the kernel log, which a container does not have — drop it to keep rsyslog quiet.
sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf
rm -f /run/rsyslogd.pid
rsyslogd
/usr/sbin/sshd

# Manager address (the package default is MANAGER_IP).
sed -i "s#<address>.*</address>#<address>${MANAGER}</address>#" "$CONF"

# The package only adds <localfile> entries for log files that existed at install time (none, during docker build).
if ! grep -q "<location>/var/log/auth.log</location>" "$CONF"; then
  sed -i '0,/<\/ossec_config>/s##  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n</ossec_config>#' "$CONF"
fi

# Rootcheck's trojan signatures flag stock container binaries (e.g. "Trojaned version of file /bin/diff", rule 510,
# level 7) — a known false positive in containers that would only add noise to the VIGIX Alert Inbox. Lab only.
sed -i '/<rootcheck>/,/<\/rootcheck>/s#<disabled>no</disabled>#<disabled>yes</disabled>#' "$CONF"

/var/ossec/bin/wazuh-control start
echo "Wazuh agent started (manager: ${MANAGER})"
exec tail -F /var/ossec/logs/ossec.log
