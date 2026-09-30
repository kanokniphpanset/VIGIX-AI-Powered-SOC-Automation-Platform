# VIGIX Attack Endpoint — real Wazuh alerts from a live Ubuntu box

A real Ubuntu 22.04 container running a **Wazuh agent (4.9.2)** enrolled to the
single-node manager. You run attacks *on this box*; Wazuh's own decoders/rules
generate genuine alerts, and everything at **rule level ≥ 7** is forwarded by the
manager's `custom-vigix` integration to the VIGIX backend
(`host.docker.internal:4000/api/v1/webhooks/siem/wazuh`).

This is the **non-mock** path — unlike `resources/mock-attacks/*.json` (hand-written
Wazuh JSON POSTed to the webhook), here the alerts are produced by the real
agent → manager → ruleset pipeline, so they exercise decoding, rule correlation,
severity mapping and VIGIX triage exactly as production telemetry would.

## Prerequisites

- The single-node Wazuh stack running: `single-node-wazuh.manager-1` (+ indexer,
  dashboard) on the `single-node_default` Docker network, with `custom-vigix`
  installed and `<level>7</level>` in its `<integration>` block.
- The VIGIX backend up on the host at port 4000 (`custom-vigix` posts to
  `host.docker.internal:4000`).

## Quick start

```bash
cd infra/docker/attack-endpoint
./run.sh up          # build + start endpoint, enroll agent to the manager
./run.sh attack      # run all 10 attacks (./run.sh attack 3 = just attack 3)
./run.sh verify      # summarize the level>=7 alerts it generated on the manager
./run.sh down        # remove endpoint + its manager agent record
```

Then check the alerts in VIGIX (they arrive as `siem_source = wazuh`):

```sql
SELECT severity, status, LEFT(raw_payload->'rule'->>'description',50) AS descr, created_at
FROM alerts WHERE created_at > now() - interval '10 minutes' ORDER BY created_at DESC;
```

## The 10 attacks and the rules they actually fire

Measured end-to-end (agent → manager → VIGIX). Levels are the *observed*
Wazuh 4.9.2 default-ruleset levels; **≥ 7 is forwarded to VIGIX**.

| # | Attack (real action on the endpoint) | Rule(s) observed | Level | → VIGIX |
|---|--------------------------------------|------------------|-------|:------:|
| 1 | SSH brute force (10 invalid users, wrong passwords) | 5710 → **5712** brute force | 10 | ✅ |
| 2 | Brute force **then** successful `victim` login | **5551** PAM multi-fail, **40112** multi-fail-then-success | 10 / 12 | ✅ |
| 3 | New user created (`useradd eviluser`) | 5901/5902 + **40501** *"attacks followed by addition of a user"* | 8 / **15** | ✅ |
| 4 | Privilege escalation (`usermod -aG sudo`) | 5901 new group / part of 40501 correlation | 8 | ✅ |
| 5 | Account deletion (`userdel`) | 5903 user/group deleted | 3 | ⚠️ below 7 |
| 6 | Malware drop — EICAR overwrites a monitored file (FIM) | **550** integrity checksum changed | 7 | ✅ |
| 7 | System file modified — `/etc/hosts`, planted binary (FIM) | **550** integrity checksum changed | 7 | ✅ |
| 8 | Rootkit artifact — `/etc/ld.so.preload` (FIM/rootcheck) | 550/554, rootcheck **510** | 7 | ✅ |
| 9 | SQL injection vs web app (12 requests → 404) | **31103** SQLi (each), **31152/31153** composites | 7 / 10 | ✅ |
| 10 | Directory traversal / common web attack (14 requests) | **31104** common web attack, **31153** composite | 6 / 10 | ✅ |

A representative full run forwarded **~55 alerts across 9 distinct rules**, and the
L12/L15 correlations auto-escalated to `high`/`critical` in VIGIX triage.

### Notes on measurability (why the payloads look the way they do)

- **Web attacks must miss (404).** A SQLi/traversal request that returns **200**
  is de-escalated by rule **31106** ("web attack returned code 200", level 6) and
  no longer counts toward the L7 SQLi rule or the composites. The requests
  therefore target a non-existent path (`/app/search.php?…`) so nginx returns 404,
  keeping them as **31103** (SQLi, level **7**) / **31104** (common web attack).
- **SQLi tokens are lowercase.** Rule 31103's `<url>` match is case-sensitive
  (`select%20`, `union%20`, `%20from%20`), so payloads use lowercase keywords.
- **Composite thresholds:** 5712 = 8 fails/120s; 31153 = 10 web attacks/120s;
  31151 = 14 HTTP-400s/90s. Loop counts are sized above these.
- **Malware = modification, not just new-file.** A brand-new file is rule 554
  (level **5**, not forwarded); overwriting a pre-seeded monitored file makes it
  rule 550 (level 7). Attack 6 overwrites `/root/invoice_2026.pdf`.
- **userdel (attack 5)** is level 3 in the stock ruleset — kept for realism as
  the tail of the account-tampering chain (add → escalate → delete); the chain's
  value shows up as the **40501 (L15)** correlation on attacks 1+3.

## How it works (files)

- `Dockerfile` — Ubuntu 22.04 + Wazuh agent 4.9.2 + sshd + nginx + rsyslog +
  auditd. Configures the agent to enroll to `$WAZUH_MANAGER` and to monitor
  `/var/log/auth.log`, `/var/log/nginx/access.log`, and FIM (realtime) on
  `/root`, `/etc`, `/var/www/html`, `/usr/local/bin`.
- `ossec-agent.conf.append` — the `<localfile>` / `<syscheck>` blocks injected
  into the agent's `ossec.conf` at build.
- `entrypoint.sh` — starts rsyslog (foreground, so it stays a live `/dev/log`
  listener and never leaves the daemon a zombie under a non-init PID 1), fixes
  log-file ownership to `syslog:adm` (else rsyslog's omfile action silently
  suspends and `auth.log` stays empty), starts sshd/nginx/auditd, enrolls the
  agent, and starts it.
- `scripts/run-attacks.sh` — the 10 attacks. `run-attacks.sh N` runs just attack N.
- `run.sh` — up / attack / verify / down driver.

## Troubleshooting

- **No SSH / account alerts:** `auth.log` must be owned `syslog:adm` and rsyslog
  must be a *live* process (not `Z` zombie). The image handles both; if you shell
  in and restart things manually, re-check `ps -eo stat,comm | grep rsyslogd`.
- **No web alerts:** confirm requests return **404** (not 200) and the agent is
  reading `/var/log/nginx/access.log` (`grep access.log /var/ossec/logs/ossec.log`).
- **Duplicate agent name on re-`up`:** `./run.sh down` first, or the manager keeps
  old `attack-endpoint` records (harmless, but clutters `agent_control -l`).
