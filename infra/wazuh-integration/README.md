# VIGIX Wazuh Integration

Wires a real Wazuh manager to VIGIX's SIEM webhook so alerts flow in
**automatically** the moment a Wazuh rule fires — no manual `curl`, no
analyst action. This is the piece that was missing: the backend has always
been able to *receive* `POST /api/v1/webhooks/siem/wazuh`, but nothing was
configured to actually call it from a real Wazuh deployment until now.

## Golden E2E test — SSH Brute Force

[`test-e2e.sh`](test-e2e.sh) drives the full Golden Scenario for real, with
nothing fabricated at any layer: it appends **only raw sshd auth-log
lines** to the real Wazuh manager's `/var/log/auth.log` (the attack
simulator never emits JSON, MITRE data, a risk score, or a decision — those
are only ever produced by the real Wazuh Manager and the real VIGIX
pipeline), then reads back every subsequent stage — Wazuh's own
decoder/rule match, the real alert it generated, VIGIX's normalization,
the real LangGraph investigation (threat intel / MITRE / RAG /
recommendation), Decision Agent's real risk/policy/approval outcome, and —
if that outcome legitimately clears approval — the real n8n execution and
its audit trail entry.

```bash
bash infra/wazuh-integration/test-e2e.sh
```

Full prerequisites (beyond the base set below): `soar-n8n` and
`soar-firewall-test-target` running (`docker compose -f
infra/docker/docker-compose.yml up -d n8n firewall-test-target`) for
steps 16-18 to be checkable; without them the script still verifies
criteria 1-15 and reports what it couldn't check rather than failing. See
the script's own header comment for the full rationale, including why it
uses a real public IP as the simulated attacker source and what
"classification" means given the live pipeline has no `classification_agent`
node today.

## How it works

Wazuh's `wazuh-integratord` daemon watches every alert the manager
generates. When one matches the `<level>` (and optional `<rule_id>`)
filter configured below, it invokes `custom-vigix` **synchronously**,
passing it a temp file containing that one alert as JSON. The script
POSTs that alert, unmodified, to VIGIX's webhook.

```
Wazuh rule fires
      │
      ▼
wazuh-integratord (level >= threshold?)
      │
      ▼
custom-vigix  (shell wrapper)
      │
      ▼
custom-vigix.py  ──POST──▶  http://<backend-host>:4000/api/v1/webhooks/siem/wazuh
                                   │
                                   ▼
                            HMAC signature checked (webhookAuth) → 202, alert stored
                            in the Alert Inbox for SOC triage (no incident / AI yet)
```

## Install — docker single-node lab (`wazuh-docker/single-node`, what VIGIX runs today)

```bash
# 1. Copy both scripts into the manager container (LF line endings — a CRLF checkout breaks /bin/sh)
tr -d '' < custom-vigix    > /tmp/custom-vigix
tr -d '' < custom-vigix.py > /tmp/custom-vigix.py
docker cp /tmp/custom-vigix    single-node-wazuh.manager-1:/var/ossec/integrations/custom-vigix
docker cp /tmp/custom-vigix.py single-node-wazuh.manager-1:/var/ossec/integrations/custom-vigix.py

# 2. Wazuh refuses to run a script with the wrong owner/mode
docker exec single-node-wazuh.manager-1 sh -c 'cd /var/ossec/integrations && chown root:wazuh custom-vigix custom-vigix.py && chmod 750 custom-vigix custom-vigix.py'
```

`requests` is already bundled with Wazuh's Python (`/var/ossec/framework/python/bin/python3`). The
`/var/ossec/integrations` and `/var/ossec/etc` directories are named Docker volumes, so both the scripts
and the config below survive container restarts.

On a non-docker manager: same two files into `/var/ossec/integrations/`, same owner/mode.

## Configure (`/var/ossec/etc/ossec.conf`)

Add inside the top-level `<ossec_config>` block:

```xml
<integration>
  <name>custom-vigix</name>
  <hook_url>http://host.docker.internal:4000/api/v1/webhooks/siem/wazuh</hook_url>
  <api_key>SIEM_WEBHOOK_SECRET from apps/backend/.env</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

- `<api_key>` — **required**. The script signs every alert with it (HMAC-SHA256 over the raw body,
  `X-Webhook-Signature: sha256=<hex>`); the backend's `webhookAuth` middleware rejects unsigned or
  wrongly signed alerts with 401, and rejects everything (500) if the backend has no
  `SIEM_WEBHOOK_SECRET`. The secret itself is never sent. Rotate it in both places together.
- `<hook_url>` — `host.docker.internal` is the Docker host from inside the manager container
  (the backend on port 4000).
- `<level>7</level>` — only alerts at level 7+ are forwarded. Severity in VIGIX still comes only from
  `rule.level` (`WazuhAdapter.mapSeverity()`).
- SCA (CIS benchmark) alerts are **skipped by the script** (`SKIPPED_RULE_GROUPS`): they are
  configuration-compliance findings, not attacks, and were ~90% of the lab agent's level 7+ alerts.

Apply the config:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
docker exec single-node-wazuh.manager-1 grep integratord /var/ossec/logs/ossec.log | tail -2
# expect: wazuh-integratord: INFO: Enabling integration for: 'custom-vigix'.
```

> Edit `/var/ossec/etc/ossec.conf` **inside the container** (the persistent volume). In this lab the
> image's init step that copies `config/wazuh_cluster/wazuh_manager.conf` over it currently fails
> earlier (on the `multigroups` copy), so changes to that host file alone are not applied. The same
> block is kept in that host file too, so a fresh deployment gets it.

## Verify it's wired up

Trigger a real rule — e.g. SSH brute force from the lab attacker against the lab agent:

```bash
docker exec vigix-lab-attacker sh -c 'for i in $(seq 1 12); do sshpass -p wrong$i ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no root@172.31.250.10 true; done'
docker exec single-node-wazuh.manager-1 tail -5 /var/ossec/logs/integrations.log
```

Expect one line per forwarded alert:

```
custom-vigix: INFO: alert id=1790487047.10079 rule=5763 forwarded — VIGIX alertId=56b828f5-… status=received duplicate=False incidentId=None
```

The alert then appears in the VIGIX Alert Inbox as **Needs review** (SOC triage; no incident and no AI
run until the SOC creates an incident).

## Notes

- **Retries**: if the POST fails (backend down, network blip), this script
  logs the failure and exits non-zero — Wazuh does not automatically
  retry a failed integration call. The alert itself is still safely
  recorded in Wazuh's own `alerts.json`/index, just never reached VIGIX
  for AI enrichment. If you need guaranteed delivery, consider replaying
  from Wazuh's own alert log rather than adding retry logic here (keeps
  this script simple and matches Wazuh's own built-in integrations'
  behavior).
- **Idempotency is free**: re-running this script twice for the same
  alert (e.g. after a manual retry) is safe — the backend's
  `externalAlertId` uniqueness check means a duplicate POST returns
  202 with `duplicate: true` instead of creating a second alert.
- **Only Wazuh is wired today**: `ISiemAdapter` supports multiple SIEMs by
  design, but only `WazuhAdapter` is implemented. Splunk/Defender/ELK need
  their own adapter (backend side) before an equivalent integration script
  here would have anywhere to send alerts meaningfully.
