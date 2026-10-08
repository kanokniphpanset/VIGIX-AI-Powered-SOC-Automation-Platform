# Wazuh evidence ingestion & Indexer re-hunt — review and proposal

Status: **REVIEW + PROPOSAL ONLY.** Nothing in code, database, configuration or incident data was changed.
Not tied to Playbook/Policy. No recommendation, containment or response was created or executed.
Date of inspection: 2026-10-08. Everything below was observed read-only (details in section 0).

## 0. What was inspected, and how

| Source | Access | Result |
|---|---|---|
| Wazuh Indexer (`https://localhost:9200`, docker `single-node-wazuh.indexer-1`, Wazuh 4.9.2) | read-only `GET`/`POST _search`, `_field_caps`, `_cat`, `_template`, `_mapping`. TLS verified against the lab root CA. | Reachable, cluster green |
| Wazuh manager container | read-only `grep` of `ossec.conf`, `ls` of `logs/archives` | Done |
| VIGIX Postgres (`soar-postgres`) | read-only `SELECT` on `alerts` in 8 databases | 286 real-format Wazuh alerts compared |
| VIGIX code | read | `WazuhAdapter`, `IngestAlertFromSiem`, `alertIocs`, `alertEvidence`, `WazuhIndexerAdapter`, `WazuhRehuntAdapter`, `RunRehuntVerification` |
| Wazuh REST API (:55500) | **not queried** | Agent inventory / rule lists via the API were not inspected |

Credentials: the indexer URL/user/password are blank in `apps/backend/.env` of this checkout. They are configured in the
`.env` of the sibling worktree `VIGIX-draft-wt`; those values were loaded into memory only and never printed or stored.

### Data provenance labels used throughout

| Label | Meaning |
|---|---|
| **REAL** | Event produced by a real agent log source (sshd/PAM/nginx/useradd/syscheck/Sysmon/PowerShell) and decoded by stock Wazuh rules |
| **REAL-PIPELINE / HARNESS-WRITTEN** | Went through the real agent → manager → rule → Indexer → `custom-vigix` pipeline, but the *log line itself* was written by the evaluation harness into `/var/log/vigix-eval/events.json` and matched by the custom `VIGIX-EVAL` rules (100300-100350). Real Wazuh behaviour, **not independent telemetry** |
| **MOCK** | Hand-written JSON in `resources/mock-attacks*/`. Used here only for comparison, never as evidence of support |

Index facts: only `wazuh-alerts-4.x-*` (9 daily indices, 4,001 alerts, 2026-09-29 → 2026-10-08), `wazuh-monitoring-*`,
`wazuh-statistics-*`, `wazuh-states-vulnerabilities-*`. **No `wazuh-archives-*`.**
Agents with alerts: `attack-endpoint` (2,602), `vigix-win10-ps` (488, Windows), `vigix-lab-agent` (452), `1f37b663418a` (239), `wazuh.manager` (216), `94469f342b4e` (4).

---

## A. Real path: Wazuh → VIGIX → Evidence → Indexer re-hunt

```
 agent log source ─▶ agent ─▶ manager: predecoder → decoder → rule ─▶ alert JSON
                                                                         │
            ┌────────────────────────────────────────────────────────────┤
            │ (1) integratord "custom-vigix"  level >= 7, skips group "sca"
            │     POST /api/v1/webhooks/siem/wazuh   (HMAC-SHA256)             (2) filebeat (alerts only; archives disabled)
            ▼                                                                       ▼
  WazuhAdapter.normalize                                                   Wazuh Indexer  wazuh-alerts-4.x-YYYY.MM.DD
   externalAlertId = alert.id                                              all alerts with level >= 3 (log_alert_level=3)
   receivedAt      = alert.timestamp   (alert creation time, NOT receipt)
   rawPayload      = body, unmodified
            ▼
  IngestAlertFromSiem   idempotent on (siemSource, externalAlertId, tenant)
   alerts.raw_payload (jsonb, lossless)   tenant = hard-coded default (TODO in webhook)
   severity from rule.level (>=14 crit, >=11 high, >=7 med, else low)
            ▼
  Incident (HIGH/CRITICAL auto, MEDIUM via Alert Inbox)
   Evidence WAZUH_ALERT.structuredData = {ruleId, level, description, agent, alertSeverity, siemSource, externalAlertId}
   IOCs = extractAlertIocs(raw_payload)  -> threat_intel_iocs (type, value, source, first/last seen; NO field path, NO role)
            ▼
  Response COMPLETED ─▶ RunRehuntVerification
   criteria = incident host (agent.name) + IOCs (agent.name/agent.ip excluded) + response target
   window   = [response.completedAt, now]
            ▼
  WazuhRehuntAdapter ─▶ _field_caps / _mapping (per-index) ─▶ _search  wazuh-alerts-4.x-*  (size 20, no pagination)
   -> matchingEvents, affectedHosts (agg), iocRecurrence, spreadDetected, threatContained, events[], truncated, skipped*
            ▼
  CreateVerification (derives RESOLVED / NOT_RESOLVED; adapter never decides)
```

Verified facts behind the diagram:
- Manager `ossec.conf`: `logall=no`, `logall_json=no`; `/etc/filebeat/filebeat.yml`: `archives.enabled: false`; `/var/ossec/logs/archives/archives.log` is 0 bytes; `GET _cat/indices/wazuh-archives*` is empty.
- `custom-vigix` forwards only `<level>7</level>` and above; the Indexer holds level ≥ 3 (`log_alert_level=3`). Level distribution in the Indexer: L3 1178, L4 11, L5 862, L6 71, L7 1641, L8 24, L10 101, L12 27, L13 72, L14 10, L15 4.
- Lossless check: all **286** real-format alerts stored in VIGIX (`alerts.raw_payload`) were matched to their Indexer document by `id`. The only differences are the two fields the Indexer pipeline adds (`@timestamp`, `input.type`). No value differed.
- `id` is unique in the Indexer (4,001 docs, 4,001 distinct, no duplicate bucket), so it is a safe key for deduplication and for linking a VIGIX alert to its Indexer document.

---

## B. Real alert samples (sensitive values masked)

Document ref = `index / _id`; `alert id` = Wazuh `id` (stored as VIGIX `externalAlertId`). `timestamp` is the manager's alert time;
`predecoder.timestamp` is the log line's own time (syslog format, **no year, no timezone**); VIGIX's true receipt time is only `alerts.created_at`.

| # | Label | Doc ref / alert id | Event time → alert time | Agent / location / decoder | Rule | Key raw paths (observed) | Extracted by VIGIX today | Missing / not extracted |
|---|---|---|---|---|---|---|---|---|
| 1 | REAL | `…2026.10.03 / 88G4AaEBT0qgUD4hg1Cp`, `1791030229.2010448` | `Oct 3 12:23:47` → `2026-10-03T12:23:49.540Z` | attack-endpoint (009) / `/var/log/auth.log` / sshd | 5712 L10, T1110, freq 8 | `data.srcip`, `data.srcuser`, `full_log`, `previous_output` (6 prior lines), `predecoder.*` | IPV4 `data.srcip`, USERNAME `data.srcuser` | `previous_output`, `srcport` (not in data), `agent.ip` role |
| 2 | REAL | `…2026.10.03 / jMGWAaEBT0qgUD4hoFAI` (rule 40112) | `Oct 3 11:46:46` → `11:46:47.357Z` | attack-endpoint / auth.log / sshd | 40112 L12 "failures followed by a success", T1078+T1110 | `data.srcip`, `data.dstuser`, `data.srcport` | IPV4, USERNAME | `srcport`; **success vs failure is only in `full_log`** ("Accepted password") |
| 3 | REAL | `…2026.10.03 / n8GfAaEBT0qgUD4hEFA9`, `1791028561.1951242` | `03/Oct/2026:11:56:00` → `11:56:01.921Z` | attack-endpoint / nginx access.log / web-accesslog | 31103 L7 "SQL injection attempt", T1190 | `data.srcip`, `data.url` (route+query), `data.id`=`404` (HTTP status), `data.protocol`=`GET` (method), `full_log` (UA `sqlmap/1.7`) | IPV4, HTTP_REQUEST (`data.url`) | status, method, user-agent (only in `full_log`) |
| 4 | REAL | `…2026.10.03 / bcGQAaEBT0qgUD4hUlC5` | file mtime `11:39:48` → `11:39:48.833Z` | attack-endpoint / `syscheck` / syscheck_new_entry | 100301 L12 (custom), T1204.002 | `syscheck.path`, `syscheck.md5_after/sha1_after/sha256_after`, `size_after=68`, `perm_after`, `uname_after`, `event=added`, `mode=realtime` (**no `data.*` at all**) | **none (0 IOCs)** | path, all three hashes, owner, event — everything |
| 5 | REAL | `…2026.10.07 / hW7RFqEBmy1Sw3JDnwdE` | scheduled scan → `2026-10-07T14:43:15Z` | wazuh.manager / syscheck | 550 L7, T1565.001 | `syscheck.path=/etc/ssl/filebeat.key`, `changed_attributes`, `*_before/*_after` | none (134 of 134 rule-550 alerts yield 0 IOCs) | as above |
| 6 | HARNESS-WRITTEN | `…2026.10.03 / HMHBAaEBT0qgUD4h0lF_`, `1791030836.2035635` | json → `12:33:56.115Z` | attack-endpoint / `/var/log/vigix-eval/events.json` / json | 100320 L13 (custom), T1071.001 | `data.srcip`=172.19.0.8 (**= agent.ip, the victim**), `data.dstip`=172.19.0.7, `data.dstport`, `data.url`, `data.dns.question.name`, `data.beacon_seq` | IPV4 ×2 (no role), URL, DOMAIN | `dstport`, `http_status`, `interval_seconds`, which IP is the source |
| 7 | HARNESS-WRITTEN | `…2026.10.03 / ssGkAaEBT0qgUD4hIVAW` | → `12:01:32.206Z` | attack-endpoint / events.json / json | 100340 L13 (custom), T1048 | `data.srcip`(victim), `data.dstip`, `data.bytes_out`, `data.file`, `data.url`, `data.dns…` | IPV4 ×2, URL, DOMAIN, FILE_PATH | `bytes_out` (volume), `duration_seconds` |
| 8 | HARNESS-WRITTEN | `…2026.10.03 / qsGhAaEBT0qgUD4h6lCr` | → `11:59:08.106Z` | attack-endpoint / events.json / json | 100330 L10, T1059.004 | `data.audit.exe`, `data.audit.pid/ppid/parent/uid/user`, `data.command`, `data.file`, `data.sha256` | PROCESS_NAME, COMMAND_LINE, FILE_PATH, SHA256 | `pid`, `ppid`, `parent`, `uid`, `user` (parent/child identity) |
| 9 | HARNESS-WRITTEN | `…2026.10.03 / ccGSAaEBT0qgUD4hAFB1` | → `11:41:41.013Z` | attack-endpoint / events.json / json | 100310 L10, T1566.002 | `data.email.from/to/subject`, `data.url`, `data.srcip`, `data.dns…` | IPV4, URL, DOMAIN | **recipient (`email.to`), sender, subject** |
| 10 | REAL | `…2026.10.03 / ycGlAaEBT0qgUD4hu1BE` | `Oct 3 12:03:18` → `12:03:18.311Z` | attack-endpoint / auth.log / vigix-usermod | 100350 L14 (custom), T1098 | `data.dstuser=evaluser`, `data.vigix_group=sudo` | USERNAME | the **group** (`vigix_group`) |
| 11 | REAL | `…2026.10.03 / xMGlAaEBT0qgUD4hu1BE` | `Oct 3 12:03:15` | attack-endpoint / auth.log / useradd | 5902 L8 "New user added", T1136 | `data.dstuser`, `uid`, `gid`, `home`, `shell` | USERNAME | uid/gid/home/shell |
| 12 | REAL | `…2026.10.03 / w8GlAaEBT0qgUD4hu1BE` (rule 5901) | `Oct 3 12:03:15` | attack-endpoint / auth.log / useradd | 5901 L8 "New group added" | **no `data.*`**; only `full_log` ("new group: name=…, GID=…") | none | group name (only in `full_log`) |
| 13 | REAL | `…2026.10.03 / kMGZAaEBT0qgUD4hEVAH` (rule 92027) | Sysmon `utcTime 11:49:26.419` | vigix-win10-ps / EventChannel / windows_eventchannel | 92027 L4 (stock), T1059.001 | `data.win.eventdata.{image,commandLine,parentImage,parentCommandLine,processGuid,processId,parentProcessId,utcTime,user,integrityLevel,hashes}`; **no `full_log`** | rule 92027 is level 4 → **never forwarded** (and would yield PROCESS_NAME/COMMAND_LINE/USERNAME) | `processGuid`, pids, `utcTime`, `hashes` ("SHA256=…" combined string) |
| 14 | REAL | `…2026.10.03 / kcGZAaEBT0qgUD4hHFC_` | Sysmon EID 22 `11:49:27.175` | vigix-win10-ps / EventChannel | 100300 L12 (custom), T1059.001 | `data.win.eventdata.{image,queryName,processGuid,processId,queryStatus,user}` | PROCESS_NAME, DOMAIN, USERNAME | `processGuid`, `processId`, `utcTime`, `queryStatus` |
| 15 | REAL | `…2026.10.03 / scEjAaEBT0qgUD4hEk9q` (rule 91822) | EID 4104 | vigix-win10-ps / EventChannel | 91822 L12, T1059.001 | `data.win.eventdata.scriptBlockText`, `scriptBlockId`; **no `full_log`** | none | the script text and id |
| 16 | REAL | `…2026.10.03 / TsH9AaEBT0qgUD4hf1Gg` (rule 60106) | EID 4624 | vigix-win10-ps / EventChannel | 60106 L3, T1078 | `targetUserName`, `logonType=5`, `logonId`, `subjectUserName`; **no `ipAddress` key** | level 3 → never forwarded | logon type/id, source (absent at source) |

Detection ≠ proof of success: e.g. #3 returned HTTP 404 (the SQLi attempt was rejected), #2 is a rule inference over failures+success, #6-#9 are
rule matches on a harness-written line. MITRE and rule names are detection metadata only. Note rule 31152 maps to `T1055` (Process Injection)
for a SQL-injection pattern — evidence that MITRE mappings on stock rules are not reliable as facts.

---

## C. Field Extraction Catalog (observed fields only)

Mapping types are from `_field_caps` on `wazuh-alerts-4.x-*` (all `keyword` unless noted; all searchable and aggregatable).
"Supporting events" are the B-table rows. *Observed* = the value as stored. *Derivation* = deterministic, no judgement. *Interpretation* = needs context; never automatic.

### C1. Envelope and provenance
| Wazuh JSON path | Type | Meaning | How to extract | Normalized field | Limits | Supported by |
|---|---|---|---|---|---|---|
| `id` | keyword | Unique alert id (`<epoch>.<seq>`) | copy | `source.alertId` (dedupe key) | unique in Indexer; one log line can raise several alerts with different ids | all |
| `timestamp` / `@timestamp` | date | Manager alert creation time (UTC) | parse | `time.detected` | not the event time; `@timestamp` only in Indexer docs | all |
| `predecoder.timestamp` | keyword | Log line time as written | parse with year/zone from `time.detected` | `time.eventReported` (derived) | no year / zone; absent for json, syscheck, EventChannel | 1, 2, 10, 11 |
| `data.win.system.systemTime`, `data.win.eventdata.utcTime` | keyword | Windows event / Sysmon event time | parse ISO | `time.event` | Windows only | 13-16 |
| `agent.id`, `agent.name`, `agent.ip` | keyword | Agent that reported | copy | `host.agentId/name/ip` | `agent.ip` is the **reporting host**, never an attacker by default | all |
| `manager.name`, `decoder.name/parent`, `location`, `input.type` | keyword | Pipeline provenance | copy | `source.manager/decoder/logSource` | — | all |
| `rule.id/level/description/groups/firedtimes/frequency`, `rule.mitre.*` | keyword/long | Detection metadata | copy | `detection.*` | detection only; MITRE can be wrong (31152→T1055) | all |
| `full_log` | text (not aggregatable, no `full_log` on EventChannel docs) | Original log text | copy, keep | `source.rawText` | the only carrier for several facts (#2, #3, #12) | 1-12 |
| `previous_output` | keyword | Prior lines for frequency rules | copy, keep | `source.priorLines` | only on frequency rules | 1 |
| *(Indexer doc)* `_index`, `_id` | — | Document reference | copy at re-hunt | `source.indexerRef` | **adapter drops `_index`** | re-hunt |

### C2. Authentication / account
| Path | Meaning | Extract | Normalized | Limits | Supported by |
|---|---|---|---|---|---|
| `data.srcip` (sshd, PAM) | Remote peer address as parsed by the sshd/PAM decoder | copy | `auth.remoteAddress` | role "attacker" is an *interpretation*; same field means *reporting host* in the harness json events | 1, 2 |
| `data.dstuser` (sshd/PAM/useradd) | Account named in the line | copy | `auth.account` | for failures on non-existent users it is the *attempted* name | 1, 2, 10, 11 |
| `data.srcuser` | Attempted user (invalid user) | copy | `auth.attemptedAccount` | — | 1 |
| `data.srcport` | Remote port | copy | `auth.remotePort` | present on sshd, not on nginx | 2 |
| outcome (success/failure) | **not a field** | derive from `rule.groups` (`authentication_failures` / `authentication_success`) or `full_log` text | `auth.result` = FAILURE/SUCCESS/UNKNOWN | rule-level inference | 1, 2 |
| `data.win.eventdata.{targetUserName,targetDomainName,subjectUserName,logonType,logonId,authenticationPackageName,processName}` (EID 4624) | Windows logon | copy | `auth.*` | `ipAddress` key absent on the only logons in the index (type 5, service) | 16 |
| `data.win.eventdata.user` (Sysmon) | `DOMAIN\user` of the process | copy (split) | `process.user` | extractor stores whole string as USERNAME | 13, 14 |
| `data.dstuser` + `data.vigix_group` | account added to group | copy | `account.changedUser`, `account.group` | `vigix_group` is a harness decoder field | 10 |
| session id | — | **not available** (only Windows `logonId` / `targetLogonId`) | `auth.sessionId` = `data.win.eventdata.targetLogonId` or null | no Linux session id | 16 |

### C3. Process
| Path | Meaning | Extract | Normalized | Limits | Supported by |
|---|---|---|---|---|---|
| `data.win.eventdata.{image,commandLine,parentImage,parentCommandLine,processId,parentProcessId,processGuid,parentProcessGuid,utcTime,integrityLevel,user,hashes}` (Sysmon EID 1) | Process creation | copy; `hashes` split on `,`/`=` into algorithm/value | `process.*` | `processGuid` is the strong per-process id; level-4 rule 92027 is below the forwarding threshold | 13 |
| `data.audit.{exe,command,pid,ppid,parent,uid,user}` | Linux process | copy | `process.*` | **only the harness json events carry this**; no real `auditd` alert exists in the index (no auditd decoder among the 14 seen) | 8 |
| `data.command`, `data.file` (json) | Command / file of the event | copy | `process.commandLine`, `file.path` | harness-specific | 8 |
| process start time | — | `data.win.eventdata.utcTime` only | `process.startTime` | Linux: not available | 13 |
| `data.win.eventdata.scriptBlockText` / `scriptBlockId` (EID 4104) | PowerShell script block | copy, keep | `process.scriptBlock` | multi-part (`messageNumber/Total`) | 15 |

### C4. Network
| Path | Meaning | Extract | Normalized | Limits | Supported by |
|---|---|---|---|---|---|
| `data.srcip`, `data.dstip`, `data.dstport` (harness json) | Flow endpoints as the harness wrote them | copy | `network.src`, `network.dst`, `network.dstPort` | `srcip` equals `agent.ip` (victim) in rules 100320/100340; direction not a field | 6, 7 |
| `data.dns.question.name`, `data.win.eventdata.queryName` (+`queryStatus`) | DNS name queried | copy | `network.dnsName` | Sysmon EID 22 is the only real DNS source | 14 |
| direction | **not a field** | derive only if `src == agent.ip` ⇒ OUTBOUND (derivation, stated) | `network.direction` (derived, nullable) | invalid when `agent.ip` is NATed | 6, 7 |
| Sysmon EID 3 `sourceIp/destinationIp` | Process network connection | — | — | **NOT MAPPED / no events** in the index | — |
| process ↔ connection link | — | not available (no EID 3, no `netstat` mapping to flows; rule 533 has only `full_log`) | null | — | — |

### C5. HTTP
| Path | Meaning | Extract | Normalized | Limits | Supported by |
|---|---|---|---|---|---|
| `data.url` (web-accesslog) | **Request target (route + query), not a URL** | copy | `http.requestTarget` | must not feed `network.dst`/URL-block logic; VIGIX already types it `HTTP_REQUEST` | 3 |
| `data.protocol` (web-accesslog) | **HTTP method** (Wazuh decoder quirk) | copy | `http.method` | name misleading | 3 |
| `data.id` (web-accesslog) | **HTTP status code** | copy | `http.status` | name misleading | 3 |
| user-agent, bytes, host header | — | only inside `full_log` | `http.userAgent` via regex on `full_log` (derivation) | brittle; absent otherwise | 3 |
| `data.url` (harness json) | An outbound URL (C2/exfil/phish) | copy | `network.url` | same path, **different meaning** than web-accesslog — disambiguate by `decoder.name` / `location` | 6, 7, 9 |

### C6. File
| Path | Meaning | Extract | Normalized | Limits | Supported by |
|---|---|---|---|---|---|
| `syscheck.path`, `syscheck.event` (added/modified/deleted), `syscheck.mode` | FIM event | copy | `file.path`, `file.operation`, `file.detectionMode` | **VIGIX ignores `syscheck.*`** | 4, 5 |
| `syscheck.md5_after/sha1_after/sha256_after` (+`_before`) | Hashes | copy | `file.hash.{md5,sha1,sha256}.{before,after}` | `data.md5` / `data.sha1` / `data.hash` are **not mapped** in the index; only `data.sha256` and `syscheck.*` are | 4, 5 |
| `syscheck.{size_after,perm_after,uname_after,gname_after,uid_after,gid_after,mtime_after,inode_after}`, `changed_attributes` | File attributes | copy | `file.*` | `size_after` is `long` | 4, 5 |
| `data.file` + `data.sha256` (harness json) | File of a process event | copy | `file.path`, `file.hash.sha256` | harness only | 8, 7 |
| `data.virustotal.*` | VirusTotal integration result | copy | `file.reputation.*` | mapped; no real VT alert observed | — |

### C7. Email / cloud / identity provider / database
| Domain | Finding |
|---|---|
| Email | `data.email.{from,to,subject}` exist **only** in the harness-written phishing event (#9). No real mail log source. |
| Cloud (`data.aws/gcp/office365/ms-graph/github`), identity provider, database | Template fields exist but **no decoder or alert of these kinds is present in this index** (decoders seen: sca, sshd, syscheck_*, pam, web-accesslog, json, windows_eventchannel, ossec, rootcheck, useradd, open-userdel, vigix-usermod). Not catalogued — would be invented. |

### C8. MITRE ATT&CK from Wazuh (`rule.mitre`)
Measured on the 1,879 alerts of level >= 7 in the Indexer: **894 carry `rule.mitre`, 985 do not** (914 are SCA rule 19007, which
`custom-vigix` skips; the rest are rules 510, 5901, 533, 19004). All 894 have exactly the three keys `id[]`, `technique[]`, `tactic[]`.

| Path | Type | Meaning | Extract | Normalized | Limits | Supported by |
|---|---|---|---|---|---|---|
| `rule.mitre.id[]` | keyword[] | Technique / sub-technique ids (`T1110`, `T1070.004`) | copy | `detection.mitre.techniques[].id` | one rule may list several (553: T1070.004 + T1485; 40501: T1068/T1136/T1203) | all |
| `rule.mitre.technique[]` | keyword[] | Technique names, **same length and order as `id[]`** (894/894) | zip with `id[]` | `detection.mitre.techniques[].name` | — | all |
| `rule.mitre.tactic[]` | keyword[] | Tactic names, **de-duplicated union, NOT aligned with `id[]`** (rule 40112: 2 ids, 5 tactics) | copy as a set | `detection.mitre.tactics[]` | never pair a tactic to a technique by index | 40112, 553 |

Rules for use: MITRE is **detection metadata, not proof the technique succeeded** and not always right (rule 31152, "multiple SQL
injection attempts", maps to T1055 Process Injection). Missing `rule.mitre` is stored as an empty list, never guessed. Today VIGIX
reads `rule.mitre.id` only (`alertSummary.ts`) and `Evidence.structuredData` drops it; tactics and names are not kept.

Observed / derived / interpreted rule for the contract: store **observed** paths verbatim; **derived** values carry `derivation` (e.g. `auth.result` from `rule.groups`); **interpreted** values (attacker, victim, destination role) are *never* written automatically — they stay `UNKNOWN` until a rule bound to `decoder.name`+`location` assigns them with its reason.

---

## D. Gap analysis

### D1. Wazuh has it and VIGIX keeps it
- The whole alert (`alerts.raw_payload`, lossless for 286/286), `rule.*`, `agent.*`, `id`, `timestamp`.

### D2. Kept in the raw payload but never reaches Evidence
- `Evidence.structuredData` (WAZUH_ALERT) holds only 7 keys. Missing: `agent.id/ip`, `decoder`, `location`, `rule.groups`, `rule.mitre`, `predecoder.*`, `previous_output`, every `data.*` and `syscheck.*` path.
- `ThreatIntelIoc` stores `(type, value, source, first/last seen)` — **no field path, no role, no source document reference, no tenant column**.

### D3. Lost or mis-read by extraction (measured on the 286 + 22 real documents)
| Gap | Evidence |
|---|---|
| **`syscheck.*` is never read.** Real FIM/malware alerts produce **0 IOCs** (rule 100301: 5/5; 550: 134/134; 553: 23/23) | `extractAlertIocs` reads only `data.{md5,sha1,sha256,hash,file}` |
| Mock/real shape divergence hides it: `TC-02` fixture puts the path and hashes under `data.*`, real alert #4 puts them under `syscheck.*` | compare `resources/mock-attacks-tc/TC-02-malware.json` with #4 |
| Phishing recipient/sender/subject dropped | #9 |
| Privilege-change **target group** dropped; for 5901/5902/useradd only the user name survives | #10-#12 |
| Windows: `processGuid`, pids, `utcTime`, `hashes` (combined `SHA256=…` string), `scriptBlockText` not extracted | #13-#15 |
| `srcip`/`dstip` emitted without role; the victim's own IP appears as an IOC; exclusion is a re-hunt-time patch (`endpointIdentity`) | #6, #7 — already documented in `target-role-defect` |
| Same path, different meaning (`data.url` route vs outbound URL; `data.protocol` = method; `data.id` = status) | #3 vs #6 |
| `receivedAt` is set from `alert.timestamp` — the alert's creation time, not receipt | `WazuhAdapter.normalize`; true receipt is `created_at` |
| Event time unavailable for json / syscheck / EventChannel (no `predecoder`); syslog time has no year | #4, #6, #13 |
| Only level ≥ 7 is forwarded: real, useful events are Indexer-only (e.g. Sysmon EID 1 rule 92027 L4, Windows logon rule 60106 L3, SSH failures rule 5710/5503 L5) | B-table #13, #16; re-hunt case A |

### D4. Not present at the source (needs telemetry, not code)
- No Sysmon EID 3 (network connection): `data.win.eventdata.sourceIp/destinationIp` are unmapped; no process↔connection link anywhere.
- No real `auditd` events; Linux process data exists only in the harness json events.
- No real DNS source on Linux; no mail gateway, proxy, firewall, DB or cloud logs.
- Windows 4624 events: `data.win.eventdata.ipAddress` is unmapped in every index, so none of the 40 indexed logons carries a source address (the sampled one is logon type 5).
- **Archives are off**: only events that triggered a rule at level ≥ 3 can be searched. "Not found" can mean "no rule fired".
- Agent connectivity gaps: `wazuh-monitoring-*` hourly snapshots show `attack-endpoint` *disconnected* in 77 of 252 snapshots, `vigix-lab-agent` 121 of 252, `vigix-win10-ps` 125 of 143. A silent agent looks identical to a clean one.

### D5. Proposed deduplication
- Alert level: `(tenantId, siemSource, alert.id)` — already enforced; keep.
- Event level (several rules on one log line, e.g. 5710 + 5503): derived `eventKey = sha256(agent.id | location | predecoder.timestamp-or-timestamp | full_log)`; store alongside, never replace `alert.id`. For EventChannel use `(agent.id, data.win.system.eventRecordID, channel)`.
- Re-hunt events: dedupe on `alert.id` (Indexer `id`), not on `_id`.

---

## E. Re-hunt design on the real Indexer

### E1. What is actually searchable
| Item | Fact |
|---|---|
| Index pattern | `wazuh-alerts-4.x-*` — **alerts only**. `wazuh-archives-4.x-*` does not exist (logall off, filebeat archives off). Not changed. |
| Template | `wazuh` (patterns alerts+archives), dynamic template `string_as_keyword`; therefore an unseen `data.*` field becomes searchable only after a document containing it is indexed (e.g. `data.md5`, `data.win.eventdata.ipAddress` are NOT MAPPED today). |
| Timestamp | both `timestamp` and `@timestamp` are `date`; the adapter already queries `timestamp`, falls back to `@timestamp` and fails on mixed/unsupported mappings. |
| Exact-match fields (all `keyword`, searchable) | `data.srcip, data.dstip, data.url, data.dns.question.name, data.sha256, data.win.eventdata.{queryName,image,commandLine,parentImage,processGuid,processId,user}, syscheck.{path,md5_after,sha1_after,sha256_after}, agent.{id,name}, rule.id, id` |
| Operators in use | `term` per IOC field inside a named `bool` (`ioc_<n>`); `terms` agg on `agent.name`; `filter` agg for IOC hits. No `full_log` (text) matching — correct. |
| Limits | `size: 20`, `track_total_hits: true`, `hosts` agg size 100, no `search_after` |

### E2. Query shape (verified live; DSL abbreviated)
Criteria come only from stored evidence (never from agent identity), window = `[response.completedAt, now]`:

```jsonc
{ "size": 20, "track_total_hits": true,
  "sort": [{"timestamp": {"order":"desc","unmapped_type":"date","missing":"_last"}},
           {"@timestamp": {"order":"desc","unmapped_type":"date","missing":"_last"}}],
  "_source": ["timestamp","@timestamp","agent.name","agent.id","rule.id","rule.level","rule.description"],
  "query": { "bool": {
     "filter": [ { /* timestamp in [start,end], else @timestamp, else missing */ } ],
     "should": [
        {"bool":{"_name":"ioc_0","minimum_should_match":1,"should":[
           {"term":{"data.srcip":{"value":"<ip>"}}}, {"term":{"data.dstip":{"value":"<ip>"}}} /* + other ip fields */]}},
        {"bool":{"_name":"ioc_1","should":[{"term":{"syscheck.sha256_after":{"value":"<sha256>"}}}, /* data.sha256, … */]}} ],
     "minimum_should_match": 1 } },
  "aggs": { "hosts": {"terms":{"field":"agent.name","size":100}},
            "ioc_events": {"filter": {/* same IOC clauses */}},
            "missing_timestamp": {"filter": {/* docs without any timestamp */}} } }
```

Proposed additions (all read-only, all on fields confirmed mapped):
1. Request `_index` and `id` (alert id) in every hit and carry both in `RehuntEvent` (today only `_id` is kept → ambiguous reference).
2. Pagination: `search_after` on `[timestamp desc, id asc]`, page size ≤ 100, hard cap (e.g. 1,000 events); on cap report `truncated=true` plus `returned/total`. The existing 20-event page is only a sample.
3. Scope by **`agent.id`**, not `agent.name` (names are reused across container restarts; ids are stable) and return `affectedAgents[{id,name}]`.
4. For process-based evidence add correlation clauses: `data.win.eventdata.processGuid` (exact), `parentProcessId`+`agent.id`+time window, `syscheck.path`+`agent.id`.
5. Search `data.win.eventdata.hashes` only after splitting (it is a combined `SHA256=…` string; exact `term` on the pure hash will not match it). Until then do not claim hash coverage for Sysmon.
6. Record coverage with each run: `max(timestamp)` of the index, per-agent `wazuh-monitoring-*` status/`lastKeepAlive` for the window, and `logall` state (archives = unavailable).
7. Data delay: end the window at `now - grace` (grace to be measured; log-time → alert-time was ~1-2 s in samples, filebeat/indexing delay was not measurable from the documents and must be measured before choosing a value).

### E3. Result classes (never collapse them)
| Class | Condition | Allowed claim |
|---|---|---|
| IN_SCOPE_ACTIVITY | corroborated match on a known host/agent | "related activity in the original scope" |
| NEW_SCOPE_ACTIVITY | corroborated match on an agent not in scope | "related activity in a new scope" — only with a correlation reason (below) |
| UNCORROBORATED_MATCH | IOC value matched, no second identifier | "value seen; relation unconfirmed" — **not** spread |
| NO_MATCH_COVERED | zero matches, query ok, searched IOC types full, agents active over the whole window | "not found in the searched scope and period" |
| INCOMPLETE | query error/timeout/partial shards, truncated, skipped IOC types, agent disconnected in window, window not covered by index | "cannot conclude" |

Correlation reasons accepted for NEW_SCOPE (any one, stated explicitly): same `processGuid`; same file `path`+hash on a different agent *within a stated causal window after the first event*; same `srcip` **and** same rule family **and** target service on the second agent within the window; same user (`dstuser`) with a logon success after failures. A hash or an IP alone is never enough. Common files (e.g. `/etc/ld.so.preload`) need an allow-list of benign system paths.

---

## F. Live results (VIGIX's own `WazuhRehuntAdapter` against the real Indexer, read-only)

Health: `configured=true, reachable=true, cluster=green, alertIndices=9`.

| # | Search (IOCs from real alerts) | Window | matching | returned | affected agents | adapter output | Observation |
|---|---|---|---|---|---|---|---|
| A | IPV4 `172.19.0.3` (attacker of real SSH/web alerts) | 10-03 12:00Z → 10-08 05:00Z | 29 | 20 | attack-endpoint | recurrence, `truncated=true`, `threatContained=false` | matches are rules 5710/5503 (L5, below forwarding threshold): proves the Indexer sees lower-level events; says nothing about attack success; page cut at 20 |
| B | DOMAIN `vigix-eval-c2.net` + URL + IPV4 `172.19.0.7` (HARNESS-WRITTEN) | from 11:00Z | 16 | 16 | attack-endpoint | recurrence | all rule 100320; with window starting 12:34Z (after the last beacon) the same query returned 0 |
| C | SHA256 + MD5 of EICAR file (real rule 100301) | from 11:40Z | 1 | 1 | attack-endpoint | recurrence | the match is rule **553 "File deleted"** via `syscheck.*_after`; `data.md5` is unmapped so only `syscheck.md5_after` answered. A *delete* event is counted as "recurrence" |
| D | DOMAIN `vigix-eval-ps-stager.test` (Sysmon EID 22) | from 11:00Z | 1 | 1 | vigix-win10-ps | recurrence | `data.win.eventdata.queryName` works on the real Windows agent |
| E | IPV4 `198.51.100.77` (never seen) | same as A | 0 | 0 | — | `threatContained=true` | control; empty is only meaningful with coverage info |
| F | IPV4 `172.19.0.3` | 2026-01-01..02 (before any data) | 0 | 0 | — | **`threatContained=true`** | window entirely outside the index range still reports "contained" — no coverage check |
| G | SHA256 of `/etc/ld.so.preload` (identical file on two containers) | 09-29 → 10-08 | 6 | 6 | attack-endpoint, 1f37b663418a | **`spreadDetected=true`** | a benign identical system file reported as spread |
| H | IPV4 `172.19.0.5` (docker peer seen on vigix-lab-agent and attack-endpoint) | 09-29 → 10-08 | 131 | 20 | vigix-lab-agent, attack-endpoint | **`spreadDetected=true`** | an IP shared by two agents reported as spread |

Limits demonstrated: (1) F/E show empty ≠ contained without coverage; (2) G/H show `spreadDetected` is "any other agent matched", i.e. IOC-only; (3) A shows truncation at 20; (4) C shows event-type blindness; (5) B shows results depend on the start boundary (as designed: events strictly after completion).
No query failed or timed out in this run. `skippedIocs` was empty in all cases (every searched category had a mapped field).

---

## G. Proposed evidence contract and step plan

### G1. Evidence record (one per Wazuh alert; nullable; `UNKNOWN` is explicit)
```text
source:    tenantId, siemSource="wazuh", alertId (Wazuh id), eventKey (derived), indexerRef{index,docId}|null,
           detectedAt, eventReportedAt|null, eventAt|null, receivedAt (VIGIX true receipt), manager, decoder, logSource, rawRef(alerts.id)
detection: ruleId, level, description, groups[],
           mitre{techniques:[{id,name}], tactics:[]} (labelled "detection metadata"; empty when rule.mitre is absent)
host:      agentId, agentName, agentIp                      // reporting host only
auth:      account, attemptedAccount, remoteAddress, remotePort, result{SUCCESS|FAILURE|UNKNOWN, derivedFrom}, logonType, sessionId
process:   image, commandLine, user, pid, ppid, guid, parentImage, parentCommandLine, parentGuid, startTime, hashes[{alg,value}], scriptBlock
network:   src, srcPort, dst, dstPort, protocol, dnsName, url, direction{value,derivedFrom}|null   // roles never defaulted
http:      method, requestTarget, status, userAgent|null
file:      path, operation, hashes{md5,sha1,sha256}{before,after}, owner, perm, size
account:   changedUser, group
email:     from, to, subject, messageId
provenance[]: each value → {path, docRef, kind: OBSERVED|DERIVED, derivation?}
```
Rules: keep the raw event untouched; every value carries the JSON path it came from; no value without a source path; roles (attacker/victim/destination) are `UNKNOWN` unless a documented rule bound to `decoder.name`+`location` sets them (with its reason); tenant is stamped from the ingest context, and the re-hunt must be bounded to the tenant's agent set because the Indexer has no tenant field.

### G2. Step plan (each step needs your approval before any change)
1. **Approve contract** (this document) and pick the first domains: auth, process (Windows), file (FIM), network (harness json).
2. **Extraction adapter, additive**: new `WazuhEvidenceExtractor` producing G1 with provenance; keep `extractAlertIocs` unchanged until parity tests pass. First fix: read `syscheck.*` (closes the 0-IOC gap) and add role-less `network.src/dst`.
3. **Persist**: store the evidence contract JSON on `Evidence.structuredData` (no schema change needed) and `sourcePath` in IOC rows (requires a migration — separate approval).
4. **Fixture truth**: regenerate `TC-02` (and any other divergent fixture) from real documents captured here, labelled MOCK, so mock tests cannot mask real gaps.
5. **Re-hunt hardening (read-only code)**: return `_index`+alert `id`, `search_after` pagination, `agent.id` scope, result classes of E3, coverage block (index max time, agent status, archives=off, skipped types), spread requires a correlation reason.
6. **Measure** filebeat/indexing delay on this stack to choose the grace window.
7. **Telemetry decisions (yours, no change now)**: enable Sysmon EID 3 / auditd / archives only if the re-hunt must see events that never raise a rule.
8. Only then: bind to Playbook/Policy.

### G3. Decisions needed from you
- Is `wazuh-alerts-*` only (no archives) acceptable for re-hunt, with INCOMPLETE reported when a rule may not have fired?
- Should level 3-6 Indexer alerts be allowed as re-hunt evidence even though VIGIX never ingests them?
- Do you want harness-written events (rules 100300-100350) kept in evaluation but excluded from "real telemetry" claims?
- Is a persistence migration for IOC `sourcePath`/`role` acceptable in step 3?
