# PB-STC-001 — Short-Term Containment

**Version:** 1.2 · **Status:** ACTIVE

## Purpose

Validate → Assess → Select Action → Prepare Plan → Approval → Execute → Verify

A generic containment process. It never hardcodes "for Brute Force, always
Block IP" — that kind of case-specific choice belongs to the matched
**Procedure**, read at runtime by AI Recommendation, using the evidence of
*this* incident. The Playbook only guarantees every incident goes through
the same 7 checkpoints, regardless of type.

## Why the framework/procedure split

> Incident แต่ละตัวไม่เหมือนกัน — Playbook = กรอบกระบวนการ, ส่วน
> Recommendation = ขั้นตอนที่เหมาะกับ Incident นี้โดยเฉพาะ, และ Runbook =
> วิธีปฏิบัติจริงของ Action นั้น

```
Short-Term Containment Playbook
              │
       Assess Incident
              │
       AI Recommendation
              │
     ┌────────┼────────┐
     ↓        ↓        ↓
 Isolate    Block IP  Disable Account   ← candidate actions, from the
    Host                                  matched Procedure's containment.yaml
     │        │        │
     └────────┼────────┘
              ↓
        Decision / Approval        ← gated by the Policy Engine (policy/),
              ↓                       never by this Playbook
        IR Team Executes           ← always human, never automated
```

## Where each piece of knowledge lives

| Question | Answered by |
|---|---|
| "ต้องทำตามกฎอะไร" — what rules apply, who must approve | **Policy** (`policy/`, already implemented) |
| "ต้องผ่าน process อะไร" — what phases must this response pass through | **This Playbook** (`manifest.yaml`) |
| "Case นี้ควรทำอะไร และเพราะอะไร" — what should THIS incident's plan contain | **AI Recommendation**, built by reading the matched Procedure |
| "ลงมือทำอย่างไร" — the exact operator steps for one chosen action | **Runbook** (referenced by `runbookRef` in each procedure's `containment.yaml`) |

## Supported incident types (Procedures)

| Procedure | Handles | Primary evidence | MVP status |
|---|---|---|---|
| `BRUTE_FORCE` | Repeated login attempts | Failed logins, source IP, username | ✅ implemented |
| `MALWARE` | Malicious file/process detected | Hash, process, file, network connection | ✅ implemented |
| `RANSOMWARE` | Encryption / ransom behavior | File modification, encryption behavior, ransom note | ✅ implemented |
| `ACCOUNT_COMPROMISE` | Account takeover / anomalous login | Successful login, unusual IP/location, privilege change | ✅ implemented (TC-04) |
| `PHISHING` | Email/URL credential theft | Sender, URL, attachment, IOC | ✅ implemented (TC-03) |
| `POWERSHELL` | Encoded / hidden PowerShell, download cradle | Command line (decoded), parent process, URL/domain, payload hash | ✅ implemented (TC-05) |
| `SQL_INJECTION` | SQL injection against a web app | HTTP request, URI/parameter, status/size, source IP | ✅ implemented (TC-06) |
| `COMMAND_AND_CONTROL` | Beaconing to attacker infrastructure | Destination IP/domain/URL, beacon interval, TI verdict, owning process | ✅ implemented (TC-07) |
| `SUSPICIOUS_PROCESS_EXECUTION` | Process from unusual path / account / parent | Path, hash, command line, parent chain, user | ✅ implemented (TC-08) |
| `DATA_EXFILTRATION` | Large / unusual outbound transfer | Destination, bytes vs baseline, staged archive, account | ✅ implemented (TC-09) |
| `PRIVILEGE_ESCALATION` | Unauthorized privilege / admin-group change | Group change event, subject account, change record | ✅ implemented (TC-10) |
| `WEB_ATTACK` | Web application attack (other than SQLi) | HTTP request, URI, source IP, XSS/RCE pattern | planned |
| `LATERAL_MOVEMENT` | Attacker pivoting between hosts | Remote login, SMB/RDP/SSH, account, destination host | planned |

Each implemented procedure has the same 5-file shape — see
`procedures/BRUTE_FORCE/` for the fullest-documented example:

```
procedures/<TYPE>/
├── procedure.yaml     # identity, objective, when this procedure applies
├── steps.yaml          # ordered step TEMPLATE (no runtime status —
│                        # that lives on the actual Response Plan instance)
├── decisions.yaml      # human decision points embedded in steps —
│                        # decided by IR/SOC, never by AI (see design doc §6)
├── containment.yaml    # candidate containment actions for this incident
│                        # type — AI picks which apply per-case, never all
│                        # of them, never a fixed single path
└── verification.yaml   # the re-hunt/verification template used to close
                         # the loop; feeds Policy's verification-override
                         # rules (RULE-009/010/011 in policy/seeds/policy.seed.ts)
```

## Non-goals (deliberately out of scope for now)

- **No MITRE ATT&CK mapping yet.** Procedures are generic-per-incident-type
  for now; attack-technique-level branching is a later layer, added inside
  a procedure once the 7-phase + per-type split is proven out.
- **No fixed action sequence anywhere.** `containment.yaml` is always a
  *catalog* AI chooses from, never a script.
- **No auto-response.** Every `containmentActions` entry that isn't
  explicitly `approvalRequired: false` needs a human sign-off before
  execution, and even the `false` ones are still executed by IR Team by
  hand — "execute" never means an automated API call in this system.

## TC evaluation cases → procedure

The 10 evaluation mock alerts (`resources/mock-attacks-tc/`) each map to one procedure. The new procedures'
`containment.yaml` use the real Action Catalog codes (`ACT-*`, runbooks `RB-*`) and exactly the `allowedActions`
of the matching runtime playbook in the database (`prisma/seeds/playbook.seed.ts`).

| TC | Attack | Procedure | DB playbook |
|---|---|---|---|
| TC-01 | Brute force | `BRUTE_FORCE` | `PB-SSH-BRUTEFORCE` |
| TC-02 | Malware | `MALWARE` | `PB-MALWARE` |
| TC-03 | Phishing | `PHISHING` | `PB-PHISHING` |
| TC-04 | Account compromise | `ACCOUNT_COMPROMISE` | `PB-ACCOUNT-COMPROMISE` |
| TC-05 | PowerShell | `POWERSHELL` | `PB-POWERSHELL` |
| TC-06 | SQL injection | `SQL_INJECTION` | `PB-SQL-INJECTION` |
| TC-07 | Command and control | `COMMAND_AND_CONTROL` | `PB-C2` |
| TC-08 | Suspicious process | `SUSPICIOUS_PROCESS_EXECUTION` | `PB-SUSPICIOUS-PROCESS` |
| TC-09 | Data exfiltration | `DATA_EXFILTRATION` | `PB-DATA-EXFIL` |
| TC-10 | Privilege escalation | `PRIVILEGE_ESCALATION` | `PB-PRIV-ESC` |

Note: the three MVP procedures (`BRUTE_FORCE`, `MALWARE`, `RANSOMWARE`) still use their original action names
(`BLOCK_SOURCE_IP`, `RUNBOOK-NET-BLOCK-IP`, …), which are not the catalog codes.

