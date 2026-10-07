# VIGIX lab "victim": Ubuntu 22.04 + Wazuh agent 4.9.2 (same version as the manager) + a real OpenSSH server.
# sshd logs through rsyslog to /var/log/auth.log, which the agent ships to the manager — so an SSH brute force
# against this container produces real sshd log lines, real Wazuh alerts and, at level >= 7, a VIGIX alert.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG WAZUH_VERSION=4.9.2-1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg openssh-server rsyslog procps \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends wazuh-agent=${WAZUH_VERSION} \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

# A normal account for "failed password for <real user>" attempts; its password is random and never used.
RUN useradd -m -s /bin/bash labuser && echo "labuser:$(head -c 24 /dev/urandom | base64)" | chpasswd

COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
