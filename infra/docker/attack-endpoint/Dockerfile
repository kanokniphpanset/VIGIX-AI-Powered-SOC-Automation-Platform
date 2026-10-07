# VIGIX attack endpoint — a REAL Ubuntu box that a Wazuh agent monitors, so
# attacks run *on this machine* generate genuine Wazuh alerts (decoded by the
# manager's own built-in rulesets) instead of hand-written mock JSON.
#
# It enrolls to the running single-node manager over the shared Docker network
# (WAZUH_MANAGER, port 1515 authd), then runs sshd + nginx + auditd so the
# agent has real auth.log / web access.log / audit events to forward. Alerts at
# level >= 7 hit the manager's custom-vigix integration -> VIGIX webhook.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
# Overridden at build/run time; must match the manager's container/DNS name on
# the single-node_default network (default below matches this repo's stack).
ENV WAZUH_MANAGER="single-node-wazuh.manager-1"
ENV WAZUH_AGENT_VERSION="4.9.2-1"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg2 lsb-release ca-certificates procps \
        rsyslog \
        openssh-server sshpass \
        nginx-light \
        auditd audispd-plugins \
        sudo iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

# --- Wazuh agent (pinned to the manager's version) ---------------------------
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="${WAZUH_MANAGER}" apt-get install -y "wazuh-agent=${WAZUH_AGENT_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# --- rsyslog: make it work headless in a container --------------------------
# imklog (kernel log reader) has no /proc/kmsg to read inside a container and
# aborts rsyslog's startup before it activates outputs (verified: with imklog
# enabled, /var/log/auth.log never gets written; disabled, imuxsock opens
# /dev/log and auth/authpriv routing works). Also pin imuxsock to /dev/log.
RUN sed -i 's/^module(load="imklog".*/#&/' /etc/rsyslog.conf \
    && sed -i 's|^module(load="imuxsock").*|module(load="imuxsock" SysSock.Use="on" SysSock.Name="/dev/log")|' /etc/rsyslog.conf

# --- sshd: allow password auth so brute force produces real auth.log lines ----
RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config \
    # a known account with a known password, so attack #2 can actually succeed
    && useradd -m -s /bin/bash victim && echo 'victim:VictimPass123!' | chpasswd \
    && echo 'root:RootPass123!' | chpasswd

# --- tiny vulnerable-looking web endpoint so SQLi/traversal hits nginx logs ---
# nginx serves a static index; the point is that the attack URLs (with SQLi /
# ../../ payloads) land in /var/log/nginx/access.log, which the agent monitors
# and the manager's web-accesslog rules (31xxx) decode.
RUN echo '<html><body>VIGIX lab app — login</body></html>' > /var/www/html/index.html

# Pre-seed the file the "malware drop" (attack 6) overwrites, so FIM reports it
# as a MODIFICATION of an existing monitored file (rule 550, level 7 -> reaches
# VIGIX) rather than only "file added" (rule 554, level 5, below the threshold).
RUN echo 'Q3 financial report — internal only.' > /root/invoice_2026.pdf

# --- agent config: enroll + monitor auth.log, web log, FIM on sensitive dirs --
COPY ossec-agent.conf.append /tmp/ossec-agent.conf.append
RUN python3 - <<'PY'
import re
cfg = "/var/ossec/etc/ossec.conf"
with open(cfg) as f:
    s = f.read()
# point at the manager (belt-and-suspenders; the deb already applied WAZUH_MANAGER)
import os
mgr = os.environ.get("WAZUH_MANAGER", "single-node-wazuh.manager-1")
s = re.sub(r"<address>[^<]*</address>", f"<address>{mgr}</address>", s, count=1)
with open("/tmp/ossec-agent.conf.append") as f:
    extra = f.read()
# inject our <localfile>/<syscheck> block just before the closing tag
s = s.replace("</ossec_config>", extra + "\n</ossec_config>", 1)
with open(cfg, "w") as f:
    f.write(s)
print("agent ossec.conf patched for manager", mgr)
PY

COPY entrypoint.sh /entrypoint.sh
COPY scripts/ /opt/attacks/
RUN chmod +x /entrypoint.sh /opt/attacks/*.sh

EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
