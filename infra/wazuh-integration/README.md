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
                            202 ACCEPTED — alert persisted, job enqueued
                            (see apps/backend's own async pipeline —
                            the AI analysis runs in the background worker,
                            never blocking this request)
```

## Install (on the Wazuh manager host)

```bash
# 1. Copy both files into Wazuh's integrations directory
sudo cp custom-vigix custom-vigix.py /var/ossec/integrations/

# 2. Permissions — Wazuh refuses to run a script with the wrong owner/mode
sudo chmod 750 /var/ossec/integrations/custom-vigix
sudo chmod 750 /var/ossec/integrations/custom-vigix.py
sudo chown root:wazuh /var/ossec/integrations/custom-vigix
sudo chown root:wazuh /var/ossec/integrations/custom-vigix.py

# 3. requests must be importable by Wazuh's own bundled Python
sudo /var/ossec/framework/python/bin/python3 -m pip install requests
```

## Configure (`/var/ossec/etc/ossec.conf`)

Add inside the top-level `<ossec_config>` block:

```xml
<integration>
  <name>custom-vigix</name>
  <hook_url>http://<backend-host>:4000/api/v1/webhooks/siem/wazuh</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

- `<level>7</level>` — only alerts at level 7+ get forwarded (Wazuh's own
  scale is 0–15; tune to taste, or drop the tag to forward everything).
  This is a coarse pre-filter on the Wazuh side — the backend's own
  `WazuhAdapter.mapSeverity()` then buckets whatever gets through into
  low/medium/high/critical (see `apps/backend/src/infrastructure/
  external-services/siem/WazuhAdapter.ts`).
- `<rule_id>` (optional, not set above) — restrict to specific rule IDs
  instead of/in addition to a level threshold.
- No `<api_key>` — this webhook has no auth today (see the Phase 5 report's
  security section); leave it unset.

Restart the manager to pick up the config:

```bash
sudo systemctl restart wazuh-manager
```

## Verify it's wired up

```bash
# Trigger literally any rule (e.g. a few bad SSH logins on a monitored host),
# then watch:
tail -f /var/ossec/logs/integrations.log
```

Expect a line like:

```
2026-08-21 ... custom-vigix: INFO: alert id=1755712345.987654 rule=5710 forwarded — backend responded ACCEPTED (executionId=...)
```

Then confirm on the VIGIX side:

```bash
curl http://<backend-host>:4000/api/executions?limit=5
```

The alert should appear, and — if the orchestration worker
(`npm run worker:dev` in `apps/backend`) is running — reach `SUCCESS`
within a few seconds.

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
  `externalAlertId` uniqueness check means a duplicate POST just returns
  `ALREADY_ACCEPTED` instead of creating a second alert/execution.
- **Only Wazuh is wired today**: `ISiemAdapter` supports multiple SIEMs by
  design, but only `WazuhAdapter` is implemented. Splunk/Defender/ELK need
  their own adapter (backend side) before an equivalent integration script
  here would have anywhere to send alerts meaningfully.
