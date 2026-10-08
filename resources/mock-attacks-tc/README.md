# TC-01…TC-10 — Evaluation mock alerts (Wazuh-shaped → VIGIX)

Ten standalone **Wazuh Manager alert JSON** files, one per evaluation case
(TC-01…TC-10). Each file is exactly the JSON the Wazuh `custom-vigix`
integration would POST to `POST /api/v1/webhooks/siem/wazuh` — i.e. it looks
like it came *through the Wazuh agent → manager → ruleset pipeline*, but is
deterministic test data so each case is reproducible and has known ground truth.

**Test data only — never trusted input.** Every alert still runs the same
validation / normalization path a real Wazuh alert does (`WazuhAdapter.normalize`,
then `IngestAlertFromSiem` → AI analysis → recommendation → verification).

This folder is **separate from `resources/mock-attacks/`** on purpose: the
`npm run e2e:mock-attacks` runner globs `resources/mock-attacks/*/case-*.json`
and only understands 5 `attackType`s, so these 10 files live here and do **not**
break that suite. They are driven by `send-tc.sh` (the real webhook), not by the
e2e runner.

## The 10 cases

Severity is what `WazuhAdapter.mapSeverity` derives from `rule.level`
(≥14 critical · ≥11 high · ≥7 medium · <7 low). Host tiers come from
`resources/assets/asset-criticality-catalog.yaml`.

| TC | File | Attack | Host (tier) | Rule / Lvl | Severity | MITRE | Primary IOCs |
|----|------|--------|-------------|-----------|----------|-------|--------------|
| 01 | `TC-01-brute-force.json` | SSH brute force | WEB-01 (high) | 5712 / 10 | medium | T1110 | ip `185.220.101.45`, user `root` |
| 02 | `TC-02-malware.json` | Malicious file (hash+VT) | WKS-FIN-07 (high) | 100301 / 12 | high | T1204.002 | sha256/md5/sha1, file path |
| 03 | `TC-03-phishing.json` | Phishing link | WKS-HR-03 (high) | 100310 / 10 | medium | T1566.002 | url, domain `vigix-mock-phish.net`, ip `45.155.205.233` |
| 04 | `TC-04-account-compromise.json` | Anomalous logon | FILESRV-01 (high) | 100200 / 12 | high | T1078 | ip `91.219.236.14`, user `j.smith` |
| 05 | `TC-05-powershell.json` | Encoded PowerShell cradle | WKS-HR-03 (high) | 100300 / 12 | high | T1059.001 | command, url, domain `vigix-mock-stager.net` |
| 06 | `TC-06-sql-injection.json` | SQL injection | WEB-01 (high) | 31103 / 10 | medium | T1190 | ip `194.87.29.10`, url (union select) |
| 07 | `TC-07-command-and-control.json` | C2 beaconing | WKS-DEV-12 (medium) | 100320 / 13 | high | T1071.001 | dstip `193.142.146.212`, domain `vigix-mock-c2.net` |
| 08 | `TC-08-suspicious-process.json` | Process from /tmp | WEB-01 (high) | 100330 / 10 | medium | T1059.004 | process `/tmp/.cache/kworkerd`, command |
| 09 | `TC-09-data-exfiltration.json` | Large egress | FILESRV-01 (high) | 100340 / 13 | high | T1048 | dstip `45.61.136.77`, domain `vigix-mock-exfil.net` |
| 10 | `TC-10-privilege-escalation.json` | Added to Domain Admins | DC-01 (**critical**) | 100350 / 15 | **critical** | T1098 | user `eviluser`, actor `svc_helpdesk` |

Notes:
- Each file carries the full Wazuh alert envelope, not just the fields VIGIX reads:
  `predecoder` / `input` / `GeoLocation` / `previous_output` where Wazuh emits them,
  `rule.mail` (+ `frequency` and compliance tags on the built-in rules 5712 / 31103),
  full `data.win.system` + `eventdata` for Windows / Sysmon events (TC-04/05/10),
  `syscheck.*` + `integration: virustotal` for TC-02, Suricata `alert` / `flow` /
  `tls` for TC-07/09, and auditd syscall fields for TC-08. GeoLocation values, GUIDs
  and SIDs are invented. Fields the IOC extractor would turn into extra indicators
  (Sysmon hashes, JA3, machine-account `subjectUserName`) are deliberately omitted so
  ground truth stays unchanged.
- **TC-02** deliberately uses the harmless **EICAR** test-file hashes — real,
  well-known, and safe to look up on VirusTotal / any CTI source.
- All attacker IPs are public/routable (VIGIX's IOC extractor drops
  non-routable / TEST-NET), and all domains are synthetic `vigix-mock-*.net`.
- Rule ids: built-in Wazuh ids where one exists (5712, 31103); the rest use the
  Wazuh custom range (100200–100399), matching the convention in
  `resources/mock-attacks/`.

## Send them into VIGIX

Prereqs: backend up on `:4000` with `SIEM_WEBHOOK_SECRET` set in
`apps/backend/.env`, and the AI orchestrator running (for the analysis step).
Use Git Bash on Windows.

```bash
cd resources/mock-attacks-tc
./send-tc.sh                        # all 10
./send-tc.sh TC-05-powershell.json  # just one
BACKEND_URL=http://localhost:4000 DELAY=3 ./send-tc.sh
```

Then confirm they landed (`siem_source = wazuh`):

```sql
SELECT severity, status, LEFT(raw_payload->'rule'->>'description',48) AS descr, created_at
FROM alerts WHERE created_at > now() - interval '15 minutes' ORDER BY created_at DESC;
```

`medium` alerts wait for SOC review before an incident is opened; `high` /
`critical` open their incident automatically at ingestion (Policy INTAKE).
