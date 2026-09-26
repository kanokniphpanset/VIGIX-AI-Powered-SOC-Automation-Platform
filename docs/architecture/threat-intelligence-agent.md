# Threat Intelligence Agent — Architecture & Operations Guide

## Overview

The **ThreatIntelligenceAgent** is a LangGraph node in the VIGIX AI-Driven SOAR Automation Platform's Python orchestrator (`apps/ai-orchestrator`). It is the first node after the pipeline's START node, running before MitreAgent and RagAgent in a sequential enrichment chain (RagAgent's query builder depends on both agents' output — see `graph/build_graph.py`).

Its responsibility is to extract every Indicator of Compromise (IOC) from an incoming alert and enrich each one against configured threat-intelligence providers.

**This repository contains two implementations.** Only one is wired into the pipeline — see the two sections immediately below before reading anything further in this document.

---

## Pipeline Position

```
START → ThreatIntelAgent → MitreAgent → RagAgent → MlRiskAgent
               ↓
          LlmAnalystAgent → ValidationAgent → DecisionAgent → ...
```

The agent writes one key to `AgentState`:

| Key | Type | Description |
|---|---|---|
| `iocs` | `list[dict]` | Per-IOC results: `{ioc_type, ioc_value, source, reputation_score, raw_response}` |

---

## Production Implementation (what actually runs)

`src/agents/threat_intel_agent/agent.py`, registered as the `threat_intel` node in
`src/graph/build_graph.py`. Confirmed via call-graph trace during a 2026-08-13
consolidation pass — see `legacy/threat_intel/README.md` for the full trace.

Deliberately simple:

```
alert_text
    ↓
src/tools/ioc_extraction_tool.py :: extract_iocs(text)   — regex: IPv4, domain, URL, MD5, SHA256
    ↓ list[{ioc_type, ioc_value}], capped at 10 to protect free-tier rate limits
[for each IOC, sequentially]
    ↓
  clients/vt_client.py   :: VirusTotalClient   (IP, domain, hash lookups)
  clients/otx_client.py  :: OtxClient          (IP, domain lookups)
  clients/misp_client.py :: MispClient         (all types)
    ↓
  reputation_score = round(malicious / (malicious+suspicious+harmless+undetected) * 100, 1)
    ↓ (from VirusTotal's stats only; None if VirusTotal has no data)
state["iocs"] = [{ioc_type, ioc_value, source: "aggregated", reputation_score, raw_response}]
```

- No caching, no typed verdict/risk-level model, no per-provider retry/backoff —
  a single sequential pass per alert.
- Any provider without a configured API key (`settings.virustotal_api_key`,
  `settings.otx_api_key`, `settings.misp_url`+`settings.misp_api_key`) is
  silently skipped for that IOC — `raw_response` just won't have that key.
  Never fails the agent.
- Consumed downstream by `ml_risk_agent/feature_engineering.py`
  (`ioc["reputation_score"]`), `rag_agent/query_builder.py`
  (`ioc["raw_response"][provider]["malwareFamily"/"categories"]`), and
  `api/database.py::persist_agent_results` (the `threat_intel_iocs` table).

Tests: `tests/agents/threat_intel_agent/test_agent.py` and
`tests/tools/test_ioc_extraction_tool.py`.

---

## Archived Design (`legacy/threat_intel/` — not wired into the pipeline)

Everything from here through "Known Limitations" describes a more sophisticated
redesign (typed verdicts, TTL cache, bounded concurrency, per-provider
retry/backoff, AbuseIPDB support) that was built but never finished being
migrated in: it references `Settings` fields that don't exist and an
IOC-extraction function that was never added (see
`legacy/threat_intel/README.md` for the exact gaps). It's kept for reference
in `apps/ai-orchestrator/legacy/threat_intel/`, not deleted, but it is
**not** what runs today — everything below this point is aspirational, not
current behavior. Its exclusive tests were removed from the active suite for
the same reason (`legacy/threat_intel/README.md` explains why fixing rather
than archiving it was out of scope for a consolidation pass).

## Archived Architecture

### Layer Responsibilities

```
agent.py          — LangGraph node entry point; delegates to ThreatIntelligenceService
service.py        — Orchestrates extraction → normalization → concurrency → aggregation
ioc_extractor.py  — Pulls IOCs from raw alert fields + free text (regex)
ioc_normalizer.py — Canonicalizes values; deduplicates by (type, value)
ioc_validator.py  — Format-checks indicators; invalid IOCs never reach providers
providers/        — Provider abstraction + per-provider HTTP clients
scoring.py        — Explainable, additive threat-score computation
aggregator.py     — Builds ThreatIntelData per IOC; ThreatIntelReport across all IOCs
cache.py          — In-process TTL cache (thread-safe; SUCCESS results only)
types.py          — Core dataclasses and enums (IocType, Verdict, RiskLevel, etc.)
errors.py         — Domain error hierarchy
```

### Processing Flow

```
raw_alert / alert_text
        ↓
  ioc_extractor.extract_from_alert()
        ↓ list[ExtractedIoc]
  ioc_normalizer.normalize_and_deduplicate()
        ↓ list[ExtractedIoc] (canonical, deduplicated)
  [for each IOC — bounded concurrency via asyncio.Semaphore]
        ↓
    ioc_validator.validate_ioc()   → invalid? → UNKNOWN ThreatIntelData, skip providers
        ↓ valid
    [for each provider — asyncio.gather]
        ↓
      ThreatIntelCache.get()       → hit? → return cached ThreatIntelProviderResult
        ↓ miss
      provider.analyze()           → ThreatIntelProviderResult
        ↓
      ThreatIntelCache.set()       (SUCCESS results only)
        ↓
  aggregator.build_threat_intel_data()   — scoring per IOC
        ↓ list[ThreatIntelData]
  aggregator.build_report()              — overall summary
        ↓
  ThreatIntelReport  → state["threat_intel_report"] + state["iocs"]
```

---

## IOC Extraction

IOCs are extracted from two sources:

1. **Structured alert fields** — checked by field-name groups:
   - IP: `src_ip`, `dst_ip`, `source_ip`, `destination_ip`, `ip`, `remote_ip`, `client_ip`
   - Domain: `domain`, `hostname`, `fqdn`, `dns`, `host`
   - URL: `url`, `uri`, `request_url`, `referrer`, `target_url`
   - Hash: `hash`, `file_hash`, `md5`, `sha1`, `sha256`, `sha2`, `checksum`
   - Email: `email`, `sender`, `from`, `from_address`, `recipient`, `to_address`
   
   Fields are checked at the top level and one level deep (e.g., `alert["source"]["ip"]`).

2. **Free text** (`alert_text`) — regex scanning for IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, email patterns.

---

## IOC Normalization

| Type | Rule |
|---|---|
| IPv4 | Unchanged |
| IPv6 | Lowercase |
| Domain | Lowercase, strip trailing `.` |
| URL | Lowercase scheme+host, remove default ports (80/443), preserve path casing, preserve query string |
| Hash | Lowercase |
| Email | Lowercase |

After normalization, IOCs are deduplicated by `(type, normalized_value)`. Empty values are dropped.

---

## Provider Architecture

### Interface

```python
class ThreatIntelProvider(ABC):
    name: str
    is_configured: bool      # property — False if API key absent
    supports(ioc_type) -> bool
    async analyze(indicator, ioc_type) -> ThreatIntelProviderResult
```

`analyze()` must never raise for expected failure modes (auth error, timeout, rate limit, malformed response, unsupported type). It returns a `ThreatIntelProviderResult` with a `ProviderStatus` enum value instead.

### Provider Status Values

| Status | Meaning |
|---|---|
| `SUCCESS` | Valid intelligence retrieved |
| `DISABLED` | API key not configured — graceful skip |
| `NOT_SUPPORTED` | Provider doesn't cover this IOC type |
| `FAILED` | Non-retryable error (auth failure, malformed response, unexpected) |
| `TIMEOUT` | Request timed out after retries |
| `RATE_LIMITED` | HTTP 429 received |
| `INVALID_INDICATOR` | Provider-level validation rejection |

### Built-in Providers

| Provider | Supported IOC Types | Key Env Var |
|---|---|---|
| VirusTotal | IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256 | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB | IPv4, IPv6 | `ABUSEIPDB_API_KEY` |
| MISP | All types | `MISP_URL` + `MISP_API_KEY` |
| OTX (AlienVault) | IPv4, IPv6, Domain | `OTX_API_KEY` |

### Adding a New Provider

1. Create `src/agents/threat_intel_agent/providers/myprovider_provider.py`:

```python
from .provider_interface import ThreatIntelProvider
from ..types import IocType, ProviderStatus, ThreatIntelProviderResult
from ._http_base import execute_request

class MyProvider(ThreatIntelProvider):
    name = "MyProvider"

    def __init__(self, api_key=None):
        self.api_key = api_key or settings.myprovider_api_key

    @property
    def is_configured(self):
        return bool(self.api_key)

    def supports(self, ioc_type):
        return ioc_type in {IocType.IPV4, IocType.DOMAIN}

    async def analyze(self, indicator, ioc_type):
        if not self.is_configured:
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.DISABLED)
        # ... HTTP call via execute_request() ...
        return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.SUCCESS, ...)
```

2. Add `MyProvider` settings to `src/config/settings.py` and `.env.example`.
3. Register in `service.py::_default_providers()`.
4. Add provider weight to `scoring.py::_PROVIDER_WEIGHTS`.
5. Write tests in `tests/agents/threat_intel_agent/test_myprovider_provider.py`.

---

## Threat Scoring

Scoring is **explainable and additive**. Every point added to the score is paired with a human-readable explanation string stored in `ThreatIntelData.explanation`.

### Base Weights

| Provider | Weight |
|---|---|
| VirusTotal | 40 |
| AbuseIPDB | 30 |
| MISP | 25 |
| OTX | 15 |
| Any unlisted provider | 15 |

### Evidence Bonuses

| Evidence | Bonus |
|---|---|
| Known malware family | +20 |
| Associated threat actor | +15 |
| Associated campaign | +10 |
| Known threat category | +10 |

### Score Formula (per provider)

- **Malicious**: `weight × max(confidence, 0.5)`
- **Suspicious**: `weight × 0.5 × max(confidence, 0.3)`
- **Clean**: no contribution to score

Score is clamped to [0, 100].

### Risk Level Bands

| Score | Risk Level |
|---|---|
| ≥ 80 | CRITICAL |
| 50–79 | HIGH |
| 20–49 | MEDIUM |
| 0–19 | LOW |
| No providers succeeded | UNKNOWN |

### Verdict Logic

| Condition | Verdict |
|---|---|
| Any provider returned malicious, OR score ≥ 50 | MALICIOUS |
| Any provider returned suspicious, OR score ≥ 20 | SUSPICIOUS |
| Providers returned results but none flagged | CLEAN |
| No provider could be queried | **UNKNOWN** (not CLEAN) |

**Critical distinction**: `UNKNOWN` means "no intelligence data was available to assess this indicator." It is never the same as `CLEAN` (which requires affirmative clean evidence from at least one provider). The `key_findings` list in `ThreatIntelReport` explicitly warns when all indicators are UNKNOWN.

---

## Error Handling

### Domain Error Hierarchy

```
ThreatIntelError
├── ThreatIntelConfigurationError   — missing/invalid config
├── InvalidIOCError                 — format validation failure
├── ThreatIntelProviderError        — provider-level failure
├── ThreatIntelTimeoutError         — request timeout
└── ThreatIntelRateLimitError       — HTTP 429
```

### Retry Policy

Retries are attempted only for **transient** errors (HTTP 408, 429, 502, 503, 504, or `httpx.TimeoutException`). The following are **never retried**:

- HTTP 401/403 (auth failure — won't succeed on retry)
- HTTP 400 (invalid indicator)
- Any 4xx not listed above

Retry config: `THREAT_INTEL_RETRY_COUNT` attempts with exponential backoff starting at `THREAT_INTEL_RETRY_BACKOFF_SECONDS`.

### Provider Failure Isolation

One provider failing never affects another's result or the overall pipeline. `ThreatIntelligenceService._query_provider()` catches all unexpected exceptions and converts them to `ProviderStatus.FAILED` with a sanitized error message — no stack traces, no secret leakage.

---

## Caching

The in-process TTL cache stores successful provider responses for the configured TTL (default 1 hour). It is **never** applied to failed, disabled, rate-limited, or timeout results — stale cache entries are always `SUCCESS` results.

Cache key: `"{provider}:{ioc_type}:{normalized_value}"`

The cache is thread-safe (uses `threading.Lock`) and is scoped to the lifetime of the `ThreatIntelligenceService` instance (module-level singleton in the LangGraph node, so per-process).

---

## Configuration Reference

All settings are loaded by `pydantic-settings` from environment variables (`.env` file or process env). No API keys are ever hardcoded or logged.

| Variable | Default | Description |
|---|---|---|
| `THREAT_INTEL_ENABLED` | `true` | Master on/off switch |
| `VIRUSTOTAL_API_KEY` | _(none)_ | VirusTotal v3 API key |
| `VIRUSTOTAL_BASE_URL` | `https://www.virustotal.com/api/v3` | |
| `VIRUSTOTAL_TIMEOUT` | `5.0` | Seconds per request |
| `ABUSEIPDB_API_KEY` | _(none)_ | AbuseIPDB API key |
| `ABUSEIPDB_BASE_URL` | `https://api.abuseipdb.com/api/v2` | |
| `ABUSEIPDB_TIMEOUT` | `5.0` | |
| `MISP_URL` | _(none)_ | MISP instance base URL |
| `MISP_API_KEY` | _(none)_ | MISP auth key |
| `MISP_TIMEOUT` | `5.0` | |
| `MISP_VERIFY_TLS` | `true` | Set `false` for dev instances with self-signed certs |
| `OTX_API_KEY` | _(none)_ | AlienVault OTX API key |
| `OTX_BASE_URL` | `https://otx.alienvault.com/api/v1/indicators` | |
| `OTX_TIMEOUT` | `5.0` | |
| `THREAT_INTEL_CACHE_ENABLED` | `true` | |
| `THREAT_INTEL_CACHE_TTL` | `3600` | Cache TTL in seconds per IOC per provider |
| `THREAT_INTEL_MAX_CONCURRENCY` | `3` | Parallel IOC analyses per alert |
| `THREAT_INTEL_RETRY_COUNT` | `2` | Max retries for transient errors |
| `THREAT_INTEL_RETRY_BACKOFF_SECONDS` | `0.5` | Initial backoff (exponential) |
| `THREAT_INTEL_MAX_IOCS_PER_ALERT` | `25` | IOC cap to bound provider cost |

---

## Testing (archived design — these test files no longer exist)

This table is kept only as a map of what the archived design *was* tested
for, in case it's ever revived; the files themselves were removed from
`tests/agents/threat_intel_agent/` since they exclusively exercised
`legacy/threat_intel/` code (see `legacy/threat_intel/README.md`).

**For the production implementation's actual, current tests**, see
`tests/agents/threat_intel_agent/test_agent.py` and
`tests/tools/test_ioc_extraction_tool.py`, referenced above.

```bash
cd apps/ai-orchestrator
python -m pytest tests/agents/threat_intel_agent/ tests/tools/ -v
```

### Test Coverage (historical — archived design)

| File (removed) | What was tested |
|---|---|
| `test_ioc_extractor.py` | All IOC types, nested fields, free text, empty/None alerts |
| `test_ioc_normalizer.py` | All normalization rules, deduplication, edge cases |
| `test_ioc_validator.py` | Valid/invalid examples for every supported IOC type |
| `test_scoring.py` | UNKNOWN/CLEAN/SUSPICIOUS/MALICIOUS, bonuses, banding, disagreement, score clamping |
| `test_cache.py` | Hit/miss/expired/failed-not-cached/disabled-cache |
| `test_abuseipdb_provider.py` | All HTTP responses (clean/suspicious/malicious/401/500/malformed) |
| `test_virustotal_provider.py` | All HTTP responses + 404-as-not-found + path construction |
| `test_aggregator.py` | build_threat_intel_data + build_report across all verdict combinations |
| `test_agent_integration.py` | Full pipeline smoke tests via mock providers + `agent.run()` state contract |

---

## Example Request / Response (archived design — illustrative only, not current output)

### Input (AgentState excerpt)

```json
{
  "alert_id": "a1b2c3",
  "raw_alert": {
    "src_ip": "185.220.101.42",
    "domain": "update-manager.xyz",
    "rule": { "description": "Suspicious outbound connection" }
  },
  "alert_text": "Process injected into svchost.exe, contacted 185.220.101.42"
}
```

### Output: `state["threat_intel_report"]`

```json
{
  "summary": {
    "total": 2,
    "malicious": 1,
    "suspicious": 1,
    "clean": 0,
    "unknown": 0
  },
  "overallRiskLevel": "HIGH",
  "overallConfidence": 0.84,
  "highestRiskIndicator": {
    "indicator": "185.220.101.42",
    "type": "IPV4",
    "verdict": "MALICIOUS",
    "riskLevel": "HIGH",
    "threatScore": 74.0,
    "confidence": 0.87,
    "malicious": true,
    "categories": ["malware", "tor-exit-node"],
    "sources": ["VirusTotal", "AbuseIPDB"],
    "explanation": [
      "+36 VirusTotal flagged indicator as malicious (confidence 0.90, 45/70 detections)",
      "+28 AbuseIPDB flagged indicator as malicious (confidence 0.95)",
      "+10 known threat categories: malware, tor-exit-node",
      "Final threat score: 74/100 (HIGH)."
    ]
  },
  "keyFindings": [
    "Analyzed 2 indicator(s): 1 malicious, 1 suspicious, 0 clean, 0 unknown.",
    "Highest-risk indicator: 185.220.101.42 (IPV4) — MALICIOUS, score 74/100.",
    "Provider coverage: AbuseIPDB, VirusTotal."
  ],
  "analyzedAt": "2026-08-10T12:00:00+00:00",
  "durationMs": 312
}
```

### Output: `state["iocs"]` (archived design's own compatibility shape — NOT the same as the real production output shown in "Production Implementation" above)

```json
[
  {
    "ioc_type": "ipv4",
    "ioc_value": "185.220.101.42",
    "source": "VirusTotal,AbuseIPDB",
    "reputation_score": 74.0,
    "raw_response": { "VirusTotal": {...}, "AbuseIPDB": {...} },
    "verdict": "MALICIOUS",
    "risk_level": "HIGH",
    "threat_score": 74.0,
    "confidence": 0.87,
    "malicious": true,
    "suspicious": false,
    "categories": ["malware", "tor-exit-node"],
    "explanation": ["..."]
  }
]
```

---

## Security Notes

- API keys are loaded exclusively from environment variables / `.env` — never hardcoded.
- Secrets are never logged; only status codes and derived counts appear in logs.
- MISP TLS verification defaults to `true`. Only set `MISP_VERIFY_TLS=false` for isolated dev instances.
- URL lookups use provider APIs (not direct HTTP fetches to the URL itself), avoiding SSRF.
- External API responses are treated as untrusted data; parsing errors return `FAILED`, never propagate exceptions.

---

## Known Limitations (archived design)

- **No Redis cache**: The TTL cache is in-process. In a multi-worker deployment, each worker maintains its own cache — no cross-process sharing.
- **OTX pulse-count heuristic**: OTX's `suspicious` threshold (1–2 pulses) is a conservative heuristic; organizations with internal MISP instances will get better coverage via MISP.
- **Email IOCs not supported by VirusTotal/AbuseIPDB/OTX**: Email indicators are extracted and validated but all built-in providers return `NOT_SUPPORTED`. A MISP instance with email attributes, or a future EmailRep provider, would cover this gap.
- **Rate limits on free tiers**: VirusTotal's free API is 4 requests/minute. `THREAT_INTEL_MAX_CONCURRENCY=3` with `THREAT_INTEL_RETRY_BACKOFF_SECONDS=0.5` provides some protection but alerts with many IOCs may still saturate free-tier limits.
