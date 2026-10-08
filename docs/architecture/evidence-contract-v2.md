# VIGIX Evidence Contract v2 — design specification

Status: **Phase 2A implemented (see "Phase 2A implementation notes" at the end).** At design time no extractor, schema, migration, re-hunt, evaluator, validator, Action Catalog, Playbook, Policy,
incident, Wazuh or Indexer change was made. This file is the specification the next phase (2A) will implement once approved.
Evidence base: `docs/architecture/wazuh-evidence-and-rehunt-review.md` (read-only inspection of the live Wazuh Indexer on 2026-10-08)
plus the extra read-only `syscheck.*` / `rule.mitre` measurements recorded in sections 4 and 5 below.
No credentials, tokens or `.env` values appear here.

Principles (non-negotiable):
1. **Detection metadata ≠ attack evidence.** Rule, level and MITRE say what Wazuh *suspected*; only observed telemetry says what *happened*.
2. **Never invent.** A field that Wazuh did not send is `null` (scalar) or `[]` (list). No value is copied from a description, guessed from a rule name, or filled from `agent.*`.
3. **Roles are not defaulted.** `agent.ip` is the reporting host, not an attacker. A role other than `UNKNOWN` needs a documented, deterministic rule.
4. **Every value is traceable** to a Wazuh JSON path of a stored alert (`alerts.raw_payload`), and the raw alert is never altered.
5. **Absence is typed**: observed / not observed / not available / incomplete are different facts.

---

## A. Current Evidence Model (what VIGIX stores today)

Verified in `apps/backend/prisma/schema.prisma`, `src/domain/investigation/*`, `src/domain/alert/alertSummary.ts`, `src/application/verification/*`.

| Layer | Today |
|---|---|
| `alerts` | `id, tenantId, externalAlertId, siemSource, rawPayload (jsonb, lossless), severity, receivedAt (= payload.timestamp), createdAt (true receipt)`; mock alerts are recognised only by the `mock-<key>-…` external-id prefix |
| `evidence` | `investigationId, alertId, type, source, origin(SYSTEM\|MANUAL), timestamp, title, description, rawData, structuredData, confidence, relevance`. `type` ∈ `WAZUH_ALERT, WAZUH_EVENT, WINDOWS_EVENT, LINUX_LOG, PROCESS_EVENT, NETWORK_CONNECTION, AUTHENTICATION_EVENT, FILE_EVENT, REGISTRY_EVENT, EMAIL, THREAT_INTELLIGENCE, ANALYST_NOTE, SCREENSHOT_ARTIFACT, QUERY_RESULT, OTHER` (the category enum already exists; `WAZUH_ALERT`/`WAZUH_EVENT` are system-only) |
| `WAZUH_ALERT` evidence content | `structuredData` = 7 keys only: `ruleId, level, description, agent, alertSeverity, siemSource, externalAlertId` (`buildAlertEvidence`). No data/syscheck/MITRE |
| `threat_intel_iocs` | `incidentId, investigationId, iocType, iocValue, source, reputationScore, rawResponse, confidence, firstSeen, lastSeen, status, sourceAlertId, addedReason`; unique `(investigationId, iocType, iocValue)`. **No role, no field path, no direct tenant column (tenant via incident)** |
| `IOC_TYPES` (22) | `IPV4, IPV6, DOMAIN, URL, MD5, SHA1, SHA256, FILE_NAME, FILE_PATH, REGISTRY_KEY, REGISTRY_VALUE, EMAIL, USERNAME, PROCESS_NAME, PROCESS_ID, HOSTNAME, MAC, CVE, CERT_FINGERPRINT, COMMAND_LINE, HTTP_REQUEST, OTHER` |
| IOC extraction (`extractAlertIocs`, read-time, not persisted at ingest) | reads `data.srcip/dstip`, `data.dns.question.name`, `data.win.eventdata.queryName`, `data.url` (→URL+DOMAIN or HTTP_REQUEST), `data.md5/sha1/sha256/hash`, `data.file`, `data.win.eventdata.{targetFilename,image,parentImage,commandLine,targetObject,details,subjectUserName,user,targetUserName}`, `data.process`, `data.audit.exe`, `data.command`, `data.srcuser/dstuser`. Returns `{iocType,value,path}`; the **path is dropped on persistence**; nothing from `syscheck.*` |
| `alertSummary` | `ruleId, ruleDescription, ruleLevel, mitreTechniques (ids only), sourceIp (=data.srcip), destinationIp (=data.dstip), host, agentIp, user` |
| MITRE | alert side: ids only (above). Incident side: `mitre_mappings(incidentId, techniqueId, tactic, confidence)` + `mitre_techniques` — produced by the MITRE agent, independent of Wazuh |
| Re-hunt (`ISiemRehuntPort`) | `RehuntEvent{id(_id), timestamp, host, agentId, ruleId, ruleLevel, ruleDescription, matchedIoc, matchedIocValues}`; `RehuntResult.source ∈ WAZUH_INDEXER\|MOCK_REHUNT`; `evidenceSource ∈ MANUAL_ENTRY\|WAZUH_INDEXER\|MOCK_REHUNT` |
| Provenance today | mock alerts: external-id prefix; mock re-hunt: `MOCK_REHUNT`; **harness-written events and real events are indistinguishable in the database** |

---

## B. Evidence Contract v2

One `EvidenceV2` document per Wazuh alert, stored in the existing `evidence.structuredData` (`contractVersion: 2`) — **no table change needed**.
Category objects are always present (stable shape); scalars are `null` and lists `[]` when Wazuh sent nothing.

```ts
interface EvidenceV2 {
  contractVersion: 2;

  provenance: {                                   // 7. Provenance and completeness
    class: "REAL_TELEMETRY" | "HARNESS_GENERATED" | "MOCK_FIXTURE";
    classBasis: string[];                         // the deterministic reasons, e.g. ["rule.groups contains vigix_eval"]
    source: {
      siem: "wazuh"; alertId: string;             // Wazuh `id`  (== alerts.externalAlertId for real alerts)
      alertRowId: string;                         // VIGIX alerts.id
      indexerRef: { index: string; docId: string } | null;   // only when read back from the Indexer (re-hunt)
      manager: string | null; decoder: { name: string | null; parent: string | null };
      location: string | null; inputType: string | null;
    };
    agent: { id: string | null; name: string | null; ip: string | null };   // the REPORTING host
    time: {
      detectedAt: string;                         // rule `timestamp` (UTC, required)
      reportedAt: string | null;                  // predecoder.timestamp (syslog; no year/zone → stored as written + resolved ISO)
      eventAt: string | null;                     // win.system.systemTime / win.eventdata.utcTime when present
      receivedAt: string;                         // VIGIX alerts.createdAt (true receipt)
    };
    completeness: {                               // per evidence category that applies to this decoder/location
      [category in EvidenceCategory]?: "OBSERVED" | "INCOMPLETE" | "NOT_AVAILABLE";
    };
    missing: string[];                            // expected Wazuh paths that were absent, e.g. ["data.win.eventdata.ipAddress"]
  };

  detection: {                                    // DETECTION METADATA — never proof of success
    rule: { id: string; level: number; description: string; groups: string[]; firedTimes: number | null; frequency: number | null };
    mitre: { techniques: { id: string; name: string | null }[]; tactics: string[] };   // see section 4
  };

  evidence: {                                     // ATTACK EVIDENCE — observed telemetry only
    network:        NetworkEvidence;
    process:        ProcessEvidence;
    file:           FileEvidence;                 // non-FIM file facts (data.file, data.sha256)
    syscheck:       SyscheckEvidence;             // FIM, see section 3
    authentication: AuthenticationEvidence;
    email:          EmailEvidence;
    powershell:     PowerShellEvidence;
    http:           HttpEvidence;                 // required by real rules 31101-31153 (web attacks)
    account:        AccountChangeEvidence;        // required by real rules 5901/5902 and custom 100350
  };

  iocs: IocV2[];                                  // see section E
  fullLog: string | null;                         // data kept as-is; never parsed into evidence by regex in v2.0
}
type EvidenceCategory = "network" | "process" | "file" | "syscheck" | "authentication" | "email" | "powershell" | "http" | "account";
```

`http` and `account` go beyond the categories you listed, deliberately: SQL-injection alerts (rule 31103, `data.url/id/protocol`) and
account/group changes (5902, 5901, 100350) are real Wazuh events that have no other home. They are optional and can be dropped if you disagree.

Required vs optional (record validity):
- **Required:** `provenance.source.alertId`, `provenance.class`, `provenance.time.detectedAt`, `provenance.time.receivedAt`, `detection.rule.{id,level,description}`, and at least one of `agent.id` / `agent.name`.
- **Everything else optional.** If a required item is absent the record is rejected as invalid input (as `WazuhAdapter` already rejects a missing `rule.description`), not padded.

Completeness semantics:

| State | Meaning | Set by |
|---|---|---|
| `OBSERVED` | at least one field of the category was present and extracted | extractor, per alert |
| `INCOMPLETE` | the category applies to this decoder/location but expected fields are absent (e.g. a logon event with no `ipAddress`) | extractor, from a static `(decoder, location) → expected paths` table |
| `NOT_AVAILABLE` | the source cannot provide it by construction, or telemetry is known not to exist in this deployment (e.g. Sysmon EID 3, archives) | extractor / re-hunt coverage |
| `NOT_OBSERVED` | **search-level only**: a re-hunt with full coverage found nothing | re-hunt (section G) |

---

## C. Wazuh → VIGIX field mapping

Only paths observed in the live Indexer or in stored VIGIX alerts. `K` = Kind: **D**etection metadata / **E**vidence (observed) / **P**rovenance.
`R` = Required / Optional. Missing source → `null` / `[]`, never filled.

### C1. Provenance and detection
| Wazuh field | VIGIX field | Category | R | K | Notes |
|---|---|---|---|---|---|
| `id` | `provenance.source.alertId` | provenance | R | P | unique in Indexer (4,001/4,001); dedupe key |
| `timestamp` (`@timestamp` in Indexer) | `time.detectedAt` | provenance | R | P | manager alert time; not event time |
| `predecoder.timestamp` | `time.reportedAt` | provenance | O | P | syslog text, no year/zone; absent for json/syscheck/EventChannel |
| `data.win.system.systemTime`, `data.win.eventdata.utcTime` | `time.eventAt` | provenance | O | P | Windows/Sysmon only |
| *(VIGIX)* `alerts.createdAt` | `time.receivedAt` | provenance | R | P | `alerts.receivedAt` is the Wazuh alert time and is **not** used for this |
| `agent.id`, `agent.name`, `agent.ip` | `agent.*` | provenance | R (id\|name) | P | reporting host; never an IOC by itself |
| `manager.name`, `decoder.name`, `decoder.parent`, `location`, `input.type` | `source.*` | provenance | O | P | drive `class` and the expected-fields table |
| `rule.id`, `rule.level`, `rule.description` | `detection.rule.*` | detection | R | D | |
| `rule.groups`, `rule.firedtimes`, `rule.frequency` | `detection.rule.*` | detection | O | D | |
| `rule.mitre.id[]`, `rule.mitre.technique[]` | `detection.mitre.techniques[]` | detection | O | D | zipped pairs |
| `rule.mitre.tactic[]` | `detection.mitre.tactics[]` | detection | O | D | set, unpaired |
| `full_log` | `fullLog` | provenance | O | E | absent on EventChannel alerts; the only carrier for some facts today |

### C2. Network
| Wazuh field | VIGIX field | R | Notes |
|---|---|---|---|
| `data.srcip` | `network.src.ip` | O | meaning depends on decoder: remote peer (sshd/PAM), client (web-accesslog), **reporting host** (harness json). Role is assigned in `iocs[]`, not here |
| `data.dstip` | `network.dst.ip` | O | harness json only in current data |
| `data.srcport`, `data.dstport` | `network.src.port` / `network.dst.port` | O | strings in the index; parse to int, `null` if not numeric |
| `data.dns.question.name`, `data.win.eventdata.queryName` | `network.dnsQuery` | O | Sysmon EID 22 is the only real DNS source |
| `data.win.eventdata.queryStatus` | `network.dnsStatus` | O | |
| `data.url` (outbound decoders: json harness) | `network.url` | O | **only** when decoder/location says it is an outbound URL; for `web-accesslog` it goes to `http.requestTarget` |
| `data.bytes_out`, `data.duration_seconds` | `network.bytesOut`, `network.durationSeconds` | O | harness json only |
| *(derived)* `src == agent.ip` | `network.direction = "OUTBOUND"` + `derivedFrom` | O | derivation only, else `null` |

### C3. Process and PowerShell
| Wazuh field | VIGIX field | R | Notes |
|---|---|---|---|
| `data.win.eventdata.image` | `process.image` | O | |
| `data.win.eventdata.commandLine` | `process.commandLine` | O | |
| `data.win.eventdata.processId`, `.processGuid` | `process.pid`, `process.guid` | O | `processGuid` is the strong per-process identity |
| `data.win.eventdata.parentImage`, `.parentCommandLine`, `.parentProcessId`, `.parentProcessGuid` | `process.parent.*` | O | |
| `data.win.eventdata.user`, `.parentUser` | `process.user`, `process.parent.user` | O | store `DOMAIN\user` split into `domain` + `name` |
| `data.win.eventdata.utcTime` | `process.startedAt` | O | Sysmon EID 1 |
| `data.win.eventdata.integrityLevel` | `process.integrityLevel` | O | |
| `data.win.eventdata.hashes` | `process.hashes[{alg,value}]` | O | combined string `SHA256=…` — split on `,` and `=`; unknown algorithms kept as written |
| `data.audit.exe`, `.command`, `.pid`, `.ppid`, `.parent`, `.uid`, `.user` | `process.*` | O | **harness json only**; no real auditd alert exists in the index |
| `data.command` | `process.commandLine` (if empty) | O | harness json |
| `data.win.eventdata.scriptBlockText`, `.scriptBlockId`, `.messageNumber`, `.messageTotal` | `powershell.scriptBlockText/Id/part/totalParts` | O | EID 4104, multi-part; keep text verbatim |
| `data.win.system.eventID`, `.channel`, `.providerName` | `process.windowsEvent{id,channel,provider}` | O | needed to interpret the above |

### C4. File (non-FIM), HTTP, account
| Wazuh field | VIGIX field | R | Notes |
|---|---|---|---|
| `data.file` | `file.path` | O | harness json |
| `data.sha256` | `file.hashes.sha256` | O | `data.md5/sha1/hash` are **not mapped** in the index, read if present |
| `data.virustotal.*` | `file.reputation` | O | mapped in template; no real VT alert observed — include only if present |
| `data.url` (web-accesslog) | `http.requestTarget` | O | route + query, **not** an outbound URL |
| `data.protocol` (web-accesslog) | `http.method` | O | Wazuh decoder quirk |
| `data.id` (web-accesslog) | `http.status` | O | Wazuh decoder quirk (status code) |
| `data.dstuser`, `data.uid`, `data.gid`, `data.home`, `data.shell` | `account.user`, `uid`, `gid`, `home`, `shell` | O | rules 5902/5901 |
| `data.vigix_group` | `account.group` | O | harness decoder (100350) |

### C5. Authentication and email
| Wazuh field | VIGIX field | R | Notes |
|---|---|---|---|
| `data.srcip`, `data.srcport` (sshd/PAM) | `authentication.remote.{ip,port}` | O | |
| `data.srcuser` | `authentication.attemptedAccount` | O | |
| `data.dstuser` | `authentication.account` | O | |
| `data.win.eventdata.targetUserName` / `targetDomainName` / `targetUserSid` | `authentication.account` (+domain, sid) | O | on group events `targetUserName` is a group — only treat as account for EID 4624/4625 |
| `data.win.eventdata.subjectUserName` / `subjectDomainName` / `subjectUserSid` | `authentication.actor.*` | O | machine accounts (`HOST$`) are kept but flagged `isMachineAccount` by suffix rule |
| `data.win.eventdata.logonType`, `.targetLogonId`, `.logonProcessName`, `.authenticationPackageName` | `authentication.logon{type,id,process,package}` | O | `targetLogonId` is the only session identifier |
| `data.win.eventdata.ipAddress` | `authentication.remote.ip` | O | **not mapped in any index today** (no indexed logon carries it) |
| *(derived)* `rule.groups` ∋ `authentication_failures` / `authentication_success` | `authentication.result` + `derivedFrom` | O | `FAILURE` / `SUCCESS` / `UNKNOWN`; rule-level inference, labelled |
| `data.email.from`, `.to`, `.subject` | `email.sender`, `email.recipients[]`, `email.subject` | O | **harness json only**; no real mail source. `messageId`/SPF/DKIM are not in any real alert → not in the contract |

---

## 3. `syscheck.*` (FIM) — measured on the live Indexer (all `wazuh-alerts-4.x-*`)

Four rules produce `syscheck.*` alerts. Presence is per document (`exists`), not assumed:

| Rule | Events | n | `mode` | `*_after` hashes/attrs | `*_before` hashes | `changed_attributes` | `diff` |
|---|---|---|---|---|---|---|---|
| 550 *Integrity checksum changed* | `modified` | 464 | realtime 433 / scheduled 31 | 464/464 | 458/464 | 464/464 | 460/464 |
| 554 *File added to the system* | `added` | 72 | realtime 72 | 72/72 | 0 | 0 | 0 |
| 553 *File deleted* | `deleted` | 71 | realtime 71 | 71/71 (**last known state**) | 0 | 0 | 0 |
| 100301 *VIGIX-EVAL executable in Downloads* (custom) | `added` | 9 | realtime 9 | 9/9 | 0 | 0 | 0 |

**Correction to the requested field list:** `syscheck.uid` and `syscheck.gid` do **not** exist (0 documents). The real fields are
`syscheck.uid_after` / `gid_after` (and `_before`), plus `uname_*`, `gname_*`, `perm_*`, `size_*` (long), `mtime_*` (date), `inode_*`,
`hard_links`, `tags`, `audit.*` (mapped; whodata — not observed in these four rules, do not rely on it).

| Wazuh path | VIGIX field (`evidence.syscheck`) | Type | Absent → | Notes |
|---|---|---|---|---|
| `syscheck.path` | `path` | string | `null` | required to build a `FILE_PATH` IOC |
| `syscheck.event` | `operation` | `"added"\|"modified"\|"deleted"` | `null` | unknown values kept verbatim, not coerced |
| `syscheck.mode` | `detectionMode` | `"realtime"\|"scheduled"` | `null` | `scheduled` ⇒ detection may lag the change by up to the scan interval; `detectedAt` ≠ change time |
| `syscheck.md5_after` / `sha1_after` / `sha256_after` | `hashes.after.{md5,sha1,sha256}` | string | `null` each | on `deleted` this is the **last known** state, not a state "after" the event — `hashes.after` is labelled `lastKnown: true` when `operation="deleted"` |
| `syscheck.md5_before` / `sha1_before` / `sha256_before` | `hashes.before.*` | string | `null` | present only on `modified` |
| `syscheck.size_after` / `size_before` | `size.{after,before}` | long | `null` | |
| `syscheck.perm_*`, `uid_*`, `gid_*`, `uname_*`, `gname_*` | `owner`/`permissions` `{after,before}` | string | `null` | |
| `syscheck.mtime_after` / `mtime_before` | `modifiedAt.{after,before}` | date | `null` | file mtime, **not** the event time |
| `syscheck.inode_*` | `inode.{after,before}` | string | `null` | |
| `syscheck.changed_attributes` | `changedAttributes` | string[] | `[]` | |
| `syscheck.diff` | `diffPresent: boolean` — **content not copied** | — | `false` | Wazuh's content diff of the file (present on 460/464 rule-550 alerts; contents not displayed in this review). May hold file contents/secrets: stays only in `alerts.raw_payload`, never in evidence, IOCs, logs or LLM prompts |
| `syscheck.hard_links`, `tags`, `audit.*` | not mapped in v2.0 | — | — | no observed values; add only when a real alert uses them |

IOC derivation from `evidence.syscheck` (deterministic): `FILE_PATH` ← `path`; `MD5/SHA1/SHA256` ← `hashes.after.*` for `added`/`modified`, and for `deleted` only
as `role=ARTIFACT` with `lastKnown` (a deleted file's hash is history, not a live indicator); `before` hashes are not indicators.
This closes the measured gap where rules 100301/550/553 yielded **0 IOCs**.

---

## 4. MITRE (detection metadata)

Measured on 1,879 alerts of level ≥ 7: 894 carry `rule.mitre`, 985 do not (914 are SCA rule 19007, skipped by `custom-vigix`). All 894 have exactly `id[]`, `technique[]`, `tactic[]`.

Rules:
- `techniques[i] = { id: mitre.id[i], name: mitre.technique[i] ?? null }` — `id[]` and `technique[]` had equal length in 894/894, but the extractor must still check equal length and set `name=null` (not shift) if they ever differ.
- `tactics = unique(mitre.tactic[])` as a **separate list**. Never pair a tactic with a technique by array position: rule 40112 has 2 ids and 5 tactics (a de-duplicated union across techniques).
- No `rule.mitre` ⇒ `{ "techniques": [], "tactics": [] }`. **Never inferred** from `rule.description` or `rule.groups`.
- MITRE is stored under `detection`, never under `evidence`, and no consumer may treat it as proof that a technique *succeeded*. Real counter-example: rule 31152 (*multiple SQL injection attempts*) maps to `T1055` Process Injection; rule 31103 returned HTTP 404, i.e. the attempt was rejected.
- The existing incident-level `mitre_mappings` (MITRE agent output) is a separate, analyst/AI layer and is not overwritten by Wazuh's mapping; v2 only adds the Wazuh-side technique **names** and **tactics** that `alertSummary` drops today.

---

## D. Missing evidence (Wazuh has it, VIGIX loses it today)

| Item | Wazuh path | Where it is lost |
|---|---|---|
| FIM path, hashes, owner, event | `syscheck.*` | extractor never reads it → 0 IOCs for rules 100301 (9), 550 (464), 553 (71), 554 (72) |
| Email sender / recipient / subject | `data.email.{from,to,subject}` | not extracted (harness phishing events) |
| Windows process identity | `processGuid`, `processId`, `parentProcessId`, `utcTime`, `hashes` | not extracted |
| PowerShell script | `data.win.eventdata.scriptBlockText`, `scriptBlockId` | not extracted (rule 91822 → 0 IOCs) |
| MITRE technique name and tactics | `rule.mitre.technique[]`, `rule.mitre.tactic[]` | `alertSummary` keeps ids only; Evidence keeps none |
| Privilege target group | `data.vigix_group` | not extracted |
| Account details | `uid, gid, home, shell` | not extracted |
| Ports, bytes, status | `srcport, dstport, bytes_out, data.id (HTTP status)` | not extracted |
| Event time | `predecoder.timestamp`, `systemTime`, `utcTime` | only the alert time is kept; `receivedAt` is mislabelled |
| Frequency context | `previous_output`, `rule.frequency`, `firedtimes` | only in raw payload |
| IOC field path and role | — | `extractAlertIocs` computes `path`, persistence drops it; role never existed |
| Source document reference | Indexer `_index` | re-hunt keeps `_id` only |

Not available at the source (telemetry, not code): Sysmon EID 3, real auditd, Linux DNS, mail-gateway, proxy/firewall, DB, cloud, source IP on indexed 4624 events, and **Wazuh archives (off)**.

---

## E. IOC schema proposal (not executed)

Current `threat_intel_iocs` has neither `sourcePath` nor `role`; one row per `(investigationId, iocType, iocValue)`.

**Problem with adding two columns to that row:** the same value can be seen at different paths/roles in different alerts
(e.g. an IP that is a `srcip` in one alert and a `dstip` in another). One row with one `role` would lose or overwrite information.

| Option | Change | Impact |
|---|---|---|
| **B (recommended)** | Keep `threat_intel_iocs` and its unique key unchanged; add `ioc_observations(id, iocId → threat_intel_iocs, alertId → alerts, evidenceId?, sourcePath, role, observedAt, provenanceClass)` | no break in existing code/unique key; role+path per observation; additive migration; backfill optional |
| A | Add `source_path`, `role` columns to `threat_intel_iocs` | simplest, but first observation wins; unique key must become `(investigationId, iocType, iocValue, role)`, which changes duplicate handling in `DuplicateIocError`, `RunRehuntVerification.carryForwardIocs` and every `@@unique` consumer |

`IocRole` (orthogonal to `IocType`, which already says *what* the value is):
`SOURCE`, `DESTINATION`, `ENDPOINT_SELF` (value equals the alert's `agent.ip`/`agent.name` — not an indicator), `ACTOR`, `TARGET`, `ARTIFACT` (hash, path, domain, process image, command line), `UNKNOWN`.
Mapping to the roles you named: `SOURCE_IP`=`IPV4/IPV6`+`SOURCE`; `DESTINATION_IP`=`IP*`+`DESTINATION`; `FILE_HASH`=`MD5/SHA1/SHA256`+`ARTIFACT`; `FILE_PATH`=`FILE_PATH`+`ARTIFACT`; `DOMAIN`=`DOMAIN`+`ARTIFACT`; `PROCESS`=`PROCESS_NAME`+`ARTIFACT`.

Role assignment rule (the only way a role other than `UNKNOWN` is written): a static table keyed by `(decoder.name, location, rule family, wazuh path)`, each row with a stated reason, e.g.
`(sshd, auth.log, data.srcip) → SOURCE` ("remote peer of the connection"); `(json, vigix-eval/events.json, data.dstip) → DESTINATION`;
`(json, vigix-eval/events.json, data.srcip) → ENDPOINT_SELF` when it equals `agent.ip`. No match ⇒ `UNKNOWN`. This also fixes, by construction,
the TC-07/TC-09 defect where the victim IP was chosen as a block target.

Proposed DDL (documented only; **not run**; migrations are tracked in `apps/backend/prisma/migrations/`, new migration would be added there):
```sql
CREATE TYPE "IocRole" AS ENUM ('SOURCE','DESTINATION','ENDPOINT_SELF','ACTOR','TARGET','ARTIFACT','UNKNOWN');
CREATE TABLE "ioc_observations" (
  "id" TEXT PRIMARY KEY, "ioc_id" TEXT NOT NULL REFERENCES "threat_intel_iocs"("id") ON DELETE CASCADE,
  "alert_id" TEXT REFERENCES "alerts"("id") ON DELETE SET NULL, "evidence_id" TEXT REFERENCES "evidence"("id") ON DELETE SET NULL,
  "source_path" TEXT NOT NULL, "role" "IocRole" NOT NULL DEFAULT 'UNKNOWN',
  "provenance_class" TEXT NOT NULL, "observed_at" TIMESTAMP(3) NOT NULL,
  UNIQUE ("ioc_id","alert_id","source_path"));
CREATE INDEX ON "ioc_observations"("ioc_id"); CREATE INDEX ON "ioc_observations"("alert_id");
```
Operational notes: there are ~20 `soar_*` databases on this host and a shared Prisma client across worktrees; the migration must be applied deliberately per database, with
`prisma generate` and the combined-schema pitfall in mind (see the project memory notes). Rollback = drop the new table/enum; no existing column changes. Tenant stays derived through `incident`/`alert`.

---

## F. Provenance model

Evidence must say what kind of source it came from. Existing repo conventions: mock alerts carry `mock-<key>-…` external ids; re-hunt uses `MOCK_REHUNT` / `WAZUH_INDEXER`; `Evidence.source`/`origin` exist. v2 reuses them and adds one derived class.

| `provenance.class` | Your term | Deterministic basis (all derivable from the stored alert) | Allowed to support "system works on real data"? |
|---|---|---|---|
| `REAL_TELEMETRY` | REAL_WAZUH_TELEMETRY | alert `id` matches `^\d{10}\.\d{6,}$`, **and** not harness, **and** (for re-hunt) found in the Indexer | yes |
| `HARNESS_GENERATED` | HARNESS_GENERATED | any of: `rule.groups` contains `vigix_eval`; `location == /var/log/vigix-eval/events.json`; `data.vigix.event_type` present | no — real pipeline, harness-written content; report separately |
| `MOCK_FIXTURE` | FIXTURE | external id has the `mock-` prefix (or equals a fixture's own id via `mockCaseOf`), or re-hunt provider `MOCK_REHUNT` | no — never evidence of real support |

`WAZUH_ALERT` is **not** a provenance class here: in this repo it is already an *evidence type* (the carrier). Using it as provenance would collide with `EVIDENCE_TYPES`.
`classBasis` records which rule fired so the class can be audited. If none of the harness/mock markers exist the alert is `REAL_TELEMETRY` *by absence of markers*; the
harness markers are therefore part of the contract and must keep being written (they are the only thing separating the two today).
Re-hunt results carry the class of every event they return, and a verification built partly on non-real events must say so.

Typed absence (what each state means, and what it forbids):

| State | Level | Meaning | Must not be read as |
|---|---|---|---|
| `OBSERVED` | alert / re-hunt | matching data present | proof of success or of spread |
| `NOT_OBSERVED` | re-hunt | query ok, **full coverage** (index covers the window, agents active the whole window, no skipped IOC types, not truncated), zero matches | "threat contained" — only "not seen in the searched scope" |
| `NOT_AVAILABLE` | coverage | telemetry cannot exist here (archives off, no EID 3, source cannot provide) | "no activity" |
| `INCOMPLETE` | alert / re-hunt | query error/timeout/partial shards, truncated, skipped types, agent disconnected, window outside index range, expected fields missing | any conclusion |

Archives are off, so **a zero-match re-hunt can only be `NOT_OBSERVED` for events that raise a rule at level ≥ 3**; otherwise it is `INCOMPLETE`.

---

## G. Re-hunt requirements (documented, not implemented)

Observed against the real Indexer with VIGIX's current `WazuhRehuntAdapter` (details in the review, section F):

| Known issue | Evidence | Requirement for the next phase |
|---|---|---|
| **same IOC ≠ spread**: `/etc/ld.so.preload` hash (identical file on two containers) ⇒ `spreadDetected=true` | live run G | `spreadDetected` needs a stated correlation reason beyond an IOC value on another agent; benign-file allow-list |
| **same IOC ≠ spread**: IP `172.19.0.5` on two agents ⇒ spread | live run H | IP alone never proves spread; require shared process/user/rule-family within a causal window |
| **file deleted ≠ recurrence** (rule 553 matched the EICAR hash as "recurrence") | live run C | classify matched events by type; deletion/cleanup does not count as recurrence |
| **no matching alert ≠ threat contained**: window before any data ⇒ `threatContained=true` | live run F | return `NOT_OBSERVED` only with the coverage conditions above, else `INCOMPLETE` |
| Truncation | live run A: 29 matches, 20 returned | `search_after` pagination with a cap; report `returned/total` |
| Event reference is partial | adapter keeps `_id`, drops `_index` and the alert `id` | return `{index, docId, alertId}` |
| Scope by agent name | names are reused across container restarts | scope by `agent.id`, return `{id,name}` |
| Agent/coverage blindness | `wazuh-monitoring-*`: `attack-endpoint` disconnected in 77/252 snapshots | include per-agent status/last keepalive for the window |
| Sysmon hashes unsearchable | `data.win.eventdata.hashes` is one combined string | search the split values or report the type as skipped |
| Provenance not carried | harness and real events indistinguishable | every returned event carries `provenance.class` |

Principles to preserve: **same IOC ≠ spread; file deleted ≠ recurrence; no matching alert ≠ threat contained.** None of this is changed in this phase.

---

## H. Implementation plan (each phase needs your explicit approval)

| Phase | Scope | Notes / exit criteria |
|---|---|---|
| **2A — Additive Wazuh extractor** | New module (e.g. `WazuhEvidenceExtractor`) producing `EvidenceV2` + `IocV2[]` with provenance and completeness; old `extractAlertIocs`/`buildAlertEvidence` untouched until parity is proven; write `contractVersion:2` into `evidence.structuredData` behind a flag | no schema change; unit tests per category; `diff` never copied; roles table static |
| **2B — Real Wazuh alert tests** | Fixtures captured from the 286+22 real documents (secrets/users masked), labelled by provenance class; golden tests per rule family (5712, 31103, 40112, 100301/550/553/554, 100300/92027/91822/60106, 100320-100350); parity test vs old extractor (new ⊇ old IOCs) | MOCK fixtures regenerated from real shapes so they can no longer hide gaps (TC-02) |
| **2C — IOC schema migration** | Option B `ioc_observations` (or Option A if you prefer) + backfill of `sourcePath` | applied per database deliberately; rollback documented |
| **2D — Re-hunt semantic fixes** | section G: correlation-reason spread, event-type aware recurrence, coverage + `NOT_OBSERVED/INCOMPLETE`, pagination, `agent.id` scope, provenance | read-only against Indexer; no config/archives change |
| **2E — Re-run TC-01…TC-10** | on the real harness, clearly separating `REAL_TELEMETRY` from `HARNESS_GENERATED`; compare with the frozen baselines | reports state which cases are harness-generated |

Decisions needed from you before 2A:
1. Keep the two extra categories `http` and `account`, or drop them?
2. `IocRole` Option B (observations table, recommended) or Option A (two columns)?
3. Provenance names: accept `REAL_TELEMETRY / HARNESS_GENERATED / MOCK_FIXTURE` (your `FIXTURE` = `MOCK_FIXTURE`; `WAZUH_ALERT` kept as an evidence type only)?
4. Store `contractVersion:2` in `evidence.structuredData` (no migration) — acceptable?
5. For `deleted` FIM events, keep the last-known hash as an `ARTIFACT` IOC with `lastKnown`, or exclude it from IOCs entirely?


---

## Phase 2A implementation notes (approved; additive, flag off by default)

Code: `apps/backend/src/domain/investigation/evidenceV2/{types,classifyProvenance,extractWazuhEvidenceV2}.ts`.
Tests: `test/WazuhEvidenceV2.test.ts` (32) and `test/AlertEvidenceContractV2.test.ts` (4) against real alerts captured on 2026-10-08
(`test/fixtures/wazuh-real/`, user/host names masked). The existing `extractAlertIocs` is untouched; a parity test asserts v2 never loses an indicator it finds.

Decisions applied (your approval did not pick options, so the recommended ones were used): `http` and `account` kept; IOC roles carried on each
`IocV2` (the `ioc_observations` table is Phase 2C); provenance names as proposed; stored in `evidence.structuredData`; deleted-file hashes kept as `ARTIFACT` IOCs with `lastKnown: true`.

Deviations from the design above, forced by the real data:
- **Storage key:** the v2 document is written to `structuredData.contractV2` (namespaced) so every existing key and consumer is unchanged; a payload v2 cannot read stores `structuredData.contractV2Error` and never blocks the evidence row. Switched on with `EVIDENCE_CONTRACT_V2=true` (read in `IncidentRepository.prisma.ts` / `InvestigationRepository.prisma.ts`); default off.
- **Fourth provenance class `UNKNOWN_ORIGIN`:** an id that is not a native Wazuh id and has no marker is never called real.
- **Native id format** is `<epoch>.<1-7 digit sequence>` (measured over all 4,001 Indexer alerts), so id shape cannot separate hand-written fixtures from real alerts. Markers are `mock-` prefix, rule group `vigix_custom`, and an optional `knownFixtureIds` set (e.g. the mock-alert catalog); a fixture with none of these (such as some `resources/mock-attacks/*` files) is classified `REAL_TELEMETRY` and `classBasis` says so.
- **`time.reportedAt`** is the resolved ISO time (year/offset taken from the alert time, null if unparseable) and `reportedAtRaw` keeps the log's own text.
- **`receivedAt`** must be the true receipt time (`alerts.created_at`); without it the v2 document is not built.
- Windows paths and users are kept verbatim, including Wazuh's doubled backslashes (`C:\Windows\…`, `HOST\user`); user is split on one or two backslashes.
- Per-alert completeness emits `OBSERVED` / `INCOMPLETE`; `NOT_AVAILABLE` stays a coverage-level state for Phase 2D.

Not done in 2A (by design): no table/migration (2C), no re-hunt change (2D), no TC re-run (2E), no consumer reads `contractV2` yet.


---

## Phase 2B results (real-alert tests)

Added: 34 real alerts (`apps/backend/test/fixtures/wazuh-real/`, each pinned to its Indexer `index/_id`, verified byte-for-byte against the live
Indexer by `scripts/verifyWazuhRealFixtures.ts`), 34 golden v2 documents, and `test/WazuhEvidenceV2.golden.test.ts` (59 tests). Together with the 2A suites: 95 tests.
Two extractor refinements came out of the tests: `fullLog` is now kept verbatim (it was being trimmed), and `provenance.source.eventKey` was added
(EventChannel record id, or hash of agent + log time + log line; `null` when neither exists - FIM/json alerts have no log time, so no key is guessed).

Three guards now run on every test run:

1. **Golden documents** - the complete v2 output of each real alert is frozen. `UPDATE_GOLDEN=1` regenerates; the diff must be reviewed.
2. **Loss detector** - every field of every real alert must appear in the v2 output or be in an explicit allow-list with a reason. Result on the 34 alerts:

| Kind | Fields | Reason |
|---|---|---|
| RESTRUCTURED | `timestamp`, `rule.groups` (trim), `data.win.eventdata.hashes` / `utcTime` | normalised or split into typed fields |
| DELIBERATE | `rule.pci_dss/gdpr/hipaa/nist_800_53/tsc/gpg13/mail`, `previous_output/log`, `data.sca.*`, most of `data.win.system.*`, Windows binary/logon-plumbing fields | not attack evidence, or kept only in `alerts.raw_payload` |
| **GAP (not extracted yet)** | `data.win.eventdata.{serviceName,serviceType,startType,imagePath,accountName}` (EID 7045 service installation - persistence), `data.title` (rootcheck finding text), `data.win.eventdata.data` (generic app event) | no category in v2 yet - candidates for a contract revision, not added without approval |

   The test also fails on stale allow-list entries, so the list cannot rot.
3. **Mock conformance** - how each TC mock differs from its real counterpart is frozen. What it shows:
   - `TC-02` carries the file path and hashes **both** under `syscheck.*` and duplicated under `data.*`; the real alert has only `syscheck.*`. With the old extractor the mock gives 4 IOCs and the real alert gives 0 - this is how the FIM gap stayed invisible.
   - `TC-04` and `TC-10` are Windows EventChannel mocks (4624/4728); the real counterparts in this lab are Linux log events (rules 40112 and 100350).
   - `TC-07` / `TC-09` use Suricata field names (`src_ip`, `dest_ip`, `tls.sni`) that no real alert in this lab has; `TC-08` carries auditd `execve/syscall` fields the real harness alert lacks.
   - The TC mocks carry `GeoLocation` and mail-auth fields; no real alert here has them (private addresses, no GeoIP, no mail log).
   - The mock is poorer than the real alert only for `TC-09` (4 vs 5 old-extractor IOCs; the real alert has `data.file`).

Decision needed (not taken): the `resources/mock-attacks-tc/` files were **not** regenerated from the real shapes. The evaluation ground truth, the mock-alert catalog and
the frozen evaluation runs are keyed to those files; rewriting TC-02 (and TC-04/07/08/09/10) would change what the old extractor and the recommendation pipeline see for the mock cases.
Options: (a) leave them frozen and rely on the conformance guard (current state); (b) add a parallel real-shaped set (`resources/mock-attacks-tc-realshape/`, labelled MOCK_FIXTURE) and move new mock tests to it; (c) rewrite the TC files and re-baseline the evaluation.


---

## Mock decision (option 2) and Phase 2C results

### Real-shaped mock set (option 2)
`resources/mock-attacks-tc-realshape/TC-01..TC-10.json` (README inside) are the real alerts with only a fixture-style `id` and the rule group `vigix_custom`
appended, so they classify as `MOCK_FIXTURE` and cannot carry a field a real alert lacks. Built offline and deterministically by
`apps/backend/scripts/buildRealShapeMocks.ts`; `test/RealShapeMocks.test.ts` (23 tests) proves each differs from its real alert only in those two places, that its v2 evidence/IOCs equal the real
alert's, that TC-02 no longer hides the FIM gap, and that the production `WazuhAdapter` accepts them. The frozen `resources/mock-attacks-tc/` set and the mock-alert catalog are unchanged; the new set is not registered in the catalog (keys would collide).

### Phase 2C - `ioc_observations` (Option B)
Code and schema are in; **no runtime database has been migrated** (see "Applying" below).

| Item | Where |
|---|---|
| Model `IocObservation` + back-relations on `ThreatIntelIoc`, `Alert`, `Evidence` | `apps/backend/prisma/schema.prisma` |
| Migration (additive, one table) | `apps/backend/prisma/migrations/20261008100000_ioc_observations/migration.sql` |
| Write path (flag-gated) | `PrismaInvestigationRepository.linkAlertIocs` - with `EVIDENCE_CONTRACT_V2=true` the cycle's IOCs come from the v2 extractor (a superset of the legacy one) and each is recorded with `source_path`, `role`, `role_basis`, `last_known`, `provenance_class`; flag off = byte-for-byte the old behaviour |
| Read path | `IInvestigationRepository.listIocObservations(investigationId)` |
| Backfill (dry-run by default) | `scripts/backfillIocObservations.ts` - inserts observations only, never creates/changes IOCs, refuses `--apply` without `--confirm-database=<name>` |
| DB tests | `test/IocObservations.postgres.test.ts` (skipped unless `IOC_OBSERVATIONS_TEST_DATABASE_URL` points at a scratch DB) |

Deviations from the DDL proposed in section E (all forced by testing on PostgreSQL 16 and by repo conventions):
- `role` and `provenance_class` are `TEXT` + `CHECK`, not PostgreSQL enums (the repo uses string columns; new values need no `ALTER TYPE`).
- The unique index is `NULLS NOT DISTINCT` - first attempt (plain unique) was verified **not** to reject a duplicate when `evidence_id` is NULL.
- Foreign keys to `alerts` / `evidence` are `ON DELETE CASCADE` (an observation is a derived fact about that row; `SET NULL` would violate the "alert or evidence" CHECK).
- Extra CHECKs: role and provenance values, `alert_id IS NOT NULL OR evidence_id IS NOT NULL`, non-blank `source_path`.
- `ThreatIntelIoc` and its unique key `(investigationId, iocType, iocValue)` are untouched. Tenant stays derived through `ioc -> incident`.
- If the flag is switched on before the migration, observation writes are skipped with one warning (`P2021`) instead of failing the investigation sync.

Verification performed (scratch databases only, since dropped): all 7 migrations applied to an empty database; the new migration applied to a pg_dump copy of `soar_platform`;
`prisma migrate diff` against the schema was empty on both (no drift); `soar_platform` itself still has no `ioc_observations` table. Constraint probes rejected a bad role, a bad
provenance class, an orphan row, a blank path, an unknown IOC and a duplicate with NULL evidence; deleting an IOC cascaded. The 6 DB tests passed on both scratch DBs, the flag-off run
left IOCs unchanged with zero observations, and the backfill on the copy created 160 observations, then 0 on re-run, with no IOC created by it.

Behaviour to know before switching the flag on: the v2 extractor finds more indicators than the legacy one (FIM path/hashes, Sysmon hashes, e-mail addresses, the reporting host as `ENDPOINT_SELF`),
so incidents get additional IOC rows. Consumers that pick targets from the IOC list must read the role (Phase 2D / the existing role validator) before the flag is used on live incidents.

### Applying (needs your go-ahead per database)
```bash
# from apps/backend, per database; example for the runtime DB
docker exec soar-postgres pg_dump -U soar -d soar_platform > ../../backups/db/soar_platform_before_ioc_observations.sql
DATABASE_URL=postgresql://.../soar_platform npx prisma migrate deploy
# stop running backends, then:  npx prisma generate     (Windows: the engine DLL is locked while a backend runs - EPERM)
DATABASE_URL=... npx ts-node --transpile-only scripts/backfillIocObservations.ts            # review
DATABASE_URL=... npx ts-node --transpile-only scripts/backfillIocObservations.ts --apply --confirm-database=soar_platform
# then EVIDENCE_CONTRACT_V2=true in the backend environment
```
Rollback: `DROP TABLE "ioc_observations";` and delete the row for the migration from `_prisma_migrations`; nothing else depends on it. The other `soar_*` evaluation databases are not migrated and are unaffected while the flag is off.


---

## Phase 2D results - re-hunt semantics

Principles now enforced in code: **same IOC != spread; file deleted != recurrence; no matching alert != threat contained.**
All Indexer access stays read-only (`GET` field caps / mappings / `_cat`, `POST _search`); no archives or configuration were changed.

### What changed
| Piece | Where |
|---|---|
| Pure semantics (class, reasons, absence rules) | `application/verification/services/classifyRehunt.ts` |
| Correlating adapter (paging, per-event facts, coverage probe) | `infrastructure/external-services/siem/CorrelatedWazuhRehuntAdapter.ts` - a subclass of `WazuhRehuntAdapter`; the plain adapter, its DSL and its tests are unchanged (one `mapHit` hook added to the base) |
| Provider selection | `createRehuntProvider`: `wazuh` now returns the correlating adapter; `mock` is unchanged (it never sets a classification, so it behaves as before) |
| Use case | `RunRehuntVerification`: passes agent id, rule groups and the original process guid / file path; **INCOMPLETE and UNCORROBORATED_MATCH create no verification** (audited as `REHUNT_FAILED` with the gaps); verification evidence stores classification, reasons, coverage, pagination |
| Errors / UI strings | `REHUNT_INCOMPLETE`, `REHUNT_UNCONFIRMED` (HTTP 409, like the other non-502 re-hunt refusals); Thai/English strings in `apps/src/i18n/catalog/common.ts` |
| Config | `WAZUH_REHUNT_PAGE_SIZE`, `WAZUH_REHUNT_RESULT_CAP`, `WAZUH_MONITORING_INDEX_PATTERN`, `WAZUH_ARCHIVES_INDEX_PATTERN`, `WAZUH_REHUNT_REQUIRE_AGENT_COVERAGE` (documented in `.env.example` and `wazuh-rehunt-integration.md`) |

### Result classes and the verdict inputs they produce
| Class | Condition | spreadDetected | iocRecurrence | threatContained | Verification |
|---|---|---|---|---|---|
| `NEW_SCOPE_ACTIVITY` | corroborated activity on an agent outside the incident scope | true | true | false | created (NOT_RESOLVED path) |
| `IN_SCOPE_ACTIVITY` | corroborated activity on the original agent(s) | false | true | false | created (NOT_RESOLVED path) |
| `UNCORROBORATED_MATCH` | an IOC value matched, nothing ties the event to the incident | false | false | false | **not created** (`REHUNT_UNCONFIRMED`) |
| `NO_MATCH_COVERED` | no activity (cleanup events do not count) **and** coverage complete | false | false | true | created (RESOLVED path) |
| `INCOMPLETE` | no activity but coverage / cap / searched IOC types insufficient | false | false | false | **not created** (`REHUNT_INCOMPLETE`) |

A positive finding stands even when coverage is incomplete (only an absence needs coverage). `matchingEvents` counts activity (cleanup excluded; the full count is `totalMatched`);
`affectedHosts` lists agents with **corroborated** activity (it used to list every agent that merely matched).

Correlation reasons (any one corroborates an event that matched an IOC): `SAME_RULE`; `SHARED_RULE_GROUP` (a non-generic group - the log-source groups
`syslog, windows, ossec, linux, local, wazuh, web, accesslog, sysmon, windows_security, pam` and the harness / fixture markers `vigix_eval, vigix_custom` never count);
`SAME_PROCESS_GUID`; `SAME_FILE_PATH` (added/modified only). Cleanup = an event whose FIM operation is `deleted`.
Coverage must show: the alert index reaches back before the window start, and every in-scope agent has status snapshots in/just before the window with none non-active (strict by default).
A bug the live harness data exposed in the tests: the harness group `vigix_eval` is shared by every harness rule, so it first made unrelated events look "corroborated"; it is now a generic group.

### Live results (real Indexer, adapter built by `createRehuntProvider`, 2026-10-08)
| # | Search | Result |
|---|---|---|
| A | SSH attacker IP `172.19.0.3`, incident rule 5712, window 10-03 12:00Z -> now | `IN_SCOPE_ACTIVITY`: 29 matches, 1 page, reasons `SHARED_RULE_GROUP` 20 + `SAME_RULE` 1; coverage incomplete (agent not active in 81 snapshots over the 5-day window) |
| B | C2 domain + URL + IP, incident rule 100320 | `IN_SCOPE_ACTIVITY`: 16 events, `SAME_RULE` 15, provenance `HARNESS_GENERATED` |
| C | EICAR hashes over a 5-day window containing the later deletion (rule 553) | deletion = `CLEANUP` (ignored 1, matchingEvents 0) but `INCOMPLETE` because of the agent-coverage gap in that long window |
| **J** | same hashes, window starting right after the response (11:40:00Z), agent active | **`NO_MATCH_COVERED`**: `totalMatched 1`, `ignoredEvents 1`, `threatContained true` - the deletion no longer counts as recurrence |
| **K** | never-seen IP, same 80-minute window, agent active | **`NO_MATCH_COVERED`**, coverage complete (`ACTIVE_THROUGHOUT`) |
| E | never-seen IP over a 5-day window | `INCOMPLETE` (agent disconnected in the window) instead of "contained" |
| F | window before any data | `INCOMPLETE`: "window starts before the oldest indexed alert" + "no agent status snapshot" (was `threatContained: true`) |
| G | `/etc/ld.so.preload` hash, unrelated incident (rule 100340) | `UNCORROBORATED_MATCH`: 3 activity events with no reason, 3 deletions ignored; `spreadDetected false` (was true) |
| H | IP `172.19.0.5` seen on two agents, incident rule 100340 | `IN_SCOPE_ACTIVITY` on the original agent only; the `vigix-lab-agent` events (rules 5710 / 5503) are not corroborated, so `spreadDetected false` (was true) |

### Known limits (stated, not hidden)
- **Path + hash correlation cannot tell a benign identical OS file from a copy.** If the incident itself is a FIM alert on that path, the same path+hash added on another host is corroborated as spread. A benign-path allow-list is future work.
- **Strict agent coverage makes lab results often INCOMPLETE:** all five lab agents are currently `disconnected` in the monitoring index, and long windows span disconnections. This is the intended answer ("cannot claim not-seen"), not a bug; `WAZUH_REHUNT_REQUIRE_AGENT_COVERAGE=false` relaxes it and the relaxation is recorded in the result.
- **Agent status is hourly:** a shorter disconnection between snapshots is invisible (stated in `coverage.limitations`).
- **Indexing delay is not measured.** The window ends at "now"; events still in flight at that moment cannot be seen. The grace period needs a measurement on the running stack (plan step 6) and is not guessed here.
- **Archives are off:** `NO_MATCH_COVERED` means "no alert-producing event", never "no event".
- Semantics of `affectedHosts` / `matchingEvents` changed for the Wazuh provider (see above). Anything that read "all matching agents" from them (reports, the spread-response policies, the frozen evaluation baselines) should be re-checked in Phase 2E; the manual-entry path and the mock provider are unchanged.
- Not implemented: Sysmon `hashes` string search, process-id correlation beyond `processGuid`, and use of the Phase 2C IOC roles inside the re-hunt verdict.

Tests added: `RehuntClassification` (22), `CorrelatedWazuhRehuntAdapter` (22), 7 cases in `RunRehuntVerification.integration`. Whole suite: 1,225 pass; the 3 failures are the pre-existing `PolicyApprovalWorkflow` (1) and `AttackSpecificRecommendation` (2).


---

## Phase 2E results - TC re-run on the real Wazuh harness

Full tables: `results/runs/clean-p2e-real-wazuh-20261008/PHASE-2E-REPORT.md` (generated by `apps/backend/scripts/eval/p2e/build-2e-report.ts`, read-only) and `PHASE-2E-CONTROL-AND-NOTES.md`; run register updated in `results/runs/README.md`.
Setup: real agent -> manager -> rules -> Indexer, Evidence Contract v2 on, correlating re-hunt, LLM recommendation agent, evaluation DBs `soar_p2e_eval` / `soar_p2e_ctrl_eval` (cloned from `soar_p1c_eval` + the `ioc_observations` migration). `soar_platform` was not touched. TC-05 not run (Windows agent offline at planning time).

| Result | Value |
|---|---|
| Clean run, 9 cases | 9/9 compliant; 8/9 re-hunted for real -> RESOLVED, all `NO_MATCH_COVERED` with complete coverage; TC-10 not re-huntable (only a user-name IOC, `INSUFFICIENT_CRITERIA` - identical in every baseline) |
| By provenance (never pooled) | REAL_TELEMETRY TC-01/04/06: 3/3 compliant, IOC 5/5, 3/3 RESOLVED. HARNESS_GENERATED TC-02/03/07/08/09/10: 6/6 compliant, IOC 17/17, 5/6 RESOLVED |
| Attributable improvement | TC-02: IOC recall 2/2 (baselines 0/2) and a real re-hunt (baselines `INSUFFICIENT_CRITERIA`) - hash and path were in `syscheck.*` |
| Not like-for-like | ground truth `9a800b…` vs the baselines' `ddb18d…` (e.g. TC-08 now expects 4 IOCs, was 2): TC-08 recall is not claimed as an improvement |
| Recurrence control (TC-01, 02, 07) | all NOT_RESOLVED / `IN_SCOPE_ACTIVITY`; TC-01 29 matches (= frozen control); TC-02's file deletion ignored as cleanup while the re-dropped file counted |
| IOC roles | recorded per case; the reporting host is `ENDPOINT_SELF` in TC-07/09; no recommended target was an `ENDPOINT_SELF` value |

Defects found by running for real (the mocked tests of 2A-2D could not see them), all fixed and covered by tests:
1. `scripts/eval/wiring.ts` lacked the generation catalog reader (Phase 1D) -> `PLAYBOOK_PROVENANCE_NOT_FOUND` before any model call.
2. Phase 2D agent coverage counted non-active snapshots up to 2 h before the window -> now only snapshots inside the window plus the latest one before it.
3. A response target that looks like a host (file path, account) was checked as an agent -> `scopeAgents` (only the alert's own agents are required).

Open points: re-hunt for IOC-less incidents (TC-10, account/privilege cases) needs a user-name or rule-based search; the Phase 2C IOC roles are recorded but the recommendation validator does not read them yet (the existing `IocRole.ts` network-role logic is separate); path+hash correlation still cannot tell a benign identical OS file; indexing delay not measured; `apps/backend/prisma/schema.prisma` and `src/domain/subtype/` are being changed by another session (a generated Prisma client older than that schema makes `Phase1APrisma.test` fail until `prisma generate` runs with the backend stopped).
