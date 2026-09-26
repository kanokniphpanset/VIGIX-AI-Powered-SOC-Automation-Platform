# Mock Wazuh Attack Fixtures (10-case E2E suite)

Deterministic test data for the VIGIX 5 attack types × 2 cases suite
(`.claude/cluade.md` §35–45). **Test data only — never trusted input.**
Every alert goes through the same validation/normalization path a real
Wazuh alert does (backend `WazuhAdapter`, AI `WazuhAlertNormalizer`).

| ID | File | Attack | Primary result | Final outcome |
|----|------|--------|----------------|---------------|
| ATK-01 | `ssh-bruteforce/case-01-resolved.json` | SSH brute force | RESOLVED | RESOLVED |
| ATK-02 | `ssh-bruteforce/case-02-not-resolved.json` | SSH brute force continues | NOT_RESOLVED | RESOLVED (round 2) |
| ATK-03 | `malware/case-01-resolved.json` | Malicious file | RESOLVED | RESOLVED |
| ATK-04 | `malware/case-02-not-resolved.json` | Malware + C2 persists | NOT_RESOLVED | ESCALATED_TO_IR (3 rounds) |
| ATK-05 | `sql-injection/case-01-resolved.json` | Single SQLi source | RESOLVED | RESOLVED |
| ATK-06 | `sql-injection/case-02-spread.json` | SQLi on multiple web hosts | SPREAD | RESOLVED (round 2) |
| ATK-07 | `account-compromise/case-01-suspicious-login.json` | Suspicious external login | RESOLVED | RESOLVED |
| ATK-08 | `account-compromise/case-02-privilege-escalation.json` | Domain Admins escalation on DC | RESOLVED (approval path) | RESOLVED / REJECTED path |
| ATK-09 | `powershell/case-01-suspicious-command.json` | Encoded PowerShell cradle | RESOLVED | RESOLVED |
| ATK-10 | `powershell/case-02-persistence.json` | PowerShell + Run-key persistence (IR review, no Manager approval — tier2 asset) | NOT_RESOLVED | RESOLVED (round 2) |

## Case file shape

```jsonc
{
  "id": "ATK-01",
  "attackType": "SSH_BRUTE_FORCE",        // SSH_BRUTE_FORCE | MALWARE | SQL_INJECTION | ACCOUNT_COMPROMISE | POWERSHELL
  "title": "...", "description": "...",
  "alert": { /* Wazuh alert JSON, POSTed to /api/v1/webhooks/siem/wazuh */ },
  "relatedAlerts": [ /* optional: further Wazuh alerts for the same incident */ ],
  "expected": {
    "severity": "medium",                // backend WazuhAdapter rule.level mapping
    "host": "WKS-DEV-12",
    "mitreTechniques": ["T1110"],
    "iocs": [{ "type": "ip", "value": "185.220.101.45" }],
    "policyInputs": { "assetTier": "tier3_medium", "ruleLevel": 10 },
    "approval": "POLICY_DECIDES",        // or APPROVAL_EXPECTED — Policy Engine stays authoritative
    "primaryResult": "RESOLVED",         // round-1 verification (RESOLVED | NOT_RESOLVED | SPREAD)
    "finalOutcome": "RESOLVED"           // RESOLVED | ESCALATED_TO_IR
  },
  "response": { "action": "...", "target": "185.220.101.45" },  // human execution simulation
  "rehunt": { "rounds": [ { "round": 1, "scenario": "NO_MATCH", "expected": {...}, "events": [ ... ] } ] }
}
```

IOC `type` values: `ip`, `domain`, `url`, `hash`, `registry`, `file`,
`process`, `command`, `user`, `request` (HTTP request path/pattern).

## Re-hunt rounds

Each `rehunt.rounds[n]` is what the SIEM returns for verification round
`n+1` of that incident. `events` are Wazuh Indexer documents (they carry
both `timestamp` and `@timestamp`) that **by definition occurred after
containment** — a mock re-hunt provider must not filter them by wall-clock
time. Matching mirrors `WazuhIndexerAdapter.buildRehuntDsl` exactly:

* an event **matches** if an IOC value appears as a phrase in `full_log`,
  `data.srcip`, `data.dstip`, `data.url`, `data.hash`, `data.md5`,
  `data.sha1`, `data.sha256` or `data.dns.question.name`, **or** its
  `rule.id` equals the original alert's rule id (any host);
* `iocRecurrence` = any IOC-matched event; `spreadDetected` = any matched
  event on a host outside the incident's hosts (alert `agent.name`, plus
  `response.target` when it is a host); `threatContained` = zero matches.

Every round also carries non-matching "noise" events, so `NO_MATCH` is
proven by filtering rather than by an empty list.

| Scenario | Meaning |
|---|---|
| `NO_MATCH` | nothing matched → candidate for RESOLVED (NO_MATCH ≠ benign) |
| `MATCH` | matched on the incident's own host(s) → NOT_RESOLVED |
| `SPREAD` | matched on another host → NOT_RESOLVED + spreadDetected |

Provider failures (`ERROR` / `TIMEOUT` / `INDEXER_UNAVAILABLE`) are modes of
the mock re-hunt provider, not case data — they must never become NO_MATCH.

## Conventions

* Built-in Wazuh rule ids where one exists (5712, 5710, 5715, 31103, 31101,
  87105, 60106); custom rules use the Wazuh custom range 100200–100399.
* Hosts come from `resources/assets/asset-criticality-catalog.yaml`
  (WEB-02 is deliberately NOT in the catalog — the spread target).
* Attacker IPs are public (the AI IOC extractor drops non-routable/TEST-NET
  addresses); domains are synthetic `vigix-mock-*.net`; ATK-03 uses the
  harmless EICAR test-file hashes, ATK-04 uses hashes of the string
  `vigix-mock-atk04-payload`.
* Some IOCs are duplicated into `data.*` (e.g. `data.url`, `data.sha256`,
  `data.srcip` on Windows events) so the indexer's IOC fields can see them.

## Tests

* `apps/ai-orchestrator/tests/fixtures/test_mock_attack_fixtures.py` — schema,
  AI normalizer, IOC extraction, re-hunt round self-consistency.
* `apps/backend/test/MockAttackFixtures.test.ts` — backend `WazuhAdapter`
  normalization and `IngestAlertFromSiemUseCase` ingestion.
