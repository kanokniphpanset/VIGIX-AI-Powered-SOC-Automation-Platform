# LlmAnalystAgent — Design Proposal (Clean Architecture)

> **Location decision:** see [`adr-llm-analyst-agent-location.md`](adr-llm-analyst-agent-location.md) —
> this module belongs in `apps/ai-orchestrator` (Python), not `apps/backend` (TypeScript).
> This document only covers the module's internal design; the ADR covers *where* it lives and why.

> **Status: design only — not implemented.** The file that runs today
> (`src/agents/llm_analyst_agent/agent.py`, ~50 lines + `prompts.py`) produces two
> free-text fields (`llm_summary`, `llm_recommendation`) from two separate LLM
> calls. This document specifies a redesign that produces four structured
> sections from a single call, without moving the agent's position in the graph
> or touching any other agent. Everything below is a proposal for review, mirroring
> the structure of [`threat-intelligence-agent.md`](threat-intelligence-agent.md)
> so the two docs read consistently.

---

## 1. Pipeline Position (unchanged)

```
START → ThreatIntelAgent → MitreAgent → RagAgent → MlRiskAgent
                                                        ↓
                                                  LlmAnalystAgent → ValidationAgent → DecisionAgent → ...
```

`build_graph.py` is not modified by this design. `LlmAnalystAgent` keeps its
single incoming edge from `ml_risk` and single outgoing edge to `validation`
(see `src/graph/build_graph.py:60-61`). Note the real graph runs `MlRiskAgent`
immediately before this node — it isn't in the four-agent input list this
design was scoped against, but its output (`risk_score`, `severity_prediction`,
`confidence_score`) is already sitting in `AgentState` by the time this node
runs, so the design treats it as optional context, never a required input.

---

## 2. Responsibilities

### In scope

| # | Responsibility | Output |
|---|---|---|
| 1 | Incident Summary | Plain-language description of what happened, grounded only in the alert + evidence already in `AgentState` |
| 2 | Root Cause Analysis | Best-supported hypothesis for how the incident occurred, with evidence citations |
| 3 | Impact Assessment | Affected assets, scope, business impact, tied to (not re-deriving) `MlRiskAgent`'s severity |
| 4 | Recommended Actions | 2–4 concrete, prioritized next steps for a human analyst |

### Explicitly out of scope (enforced structurally, see §7)

- Querying threat intelligence providers (ThreatIntelAgent's job)
- Searching playbooks / the knowledge base directly (RagAgent's job — this
  agent only *reads* `state["rag_result"]`, already retrieved)
- Mapping MITRE ATT&CK techniques (MitreAgent's job)
- Executing any response action (DecisionAgent + downstream automation's job)
- Making the auto-response / human-approval / dismiss decision (DecisionAgent's job)

This agent is a **pure reasoning/synthesis step**: read what's already in
`AgentState`, produce a structured written analysis, write it back. It never
performs I/O other than the one LLM call.

---

## 3. Input Contract

All inputs are read from `AgentState` (`src/graph/state.py`) — this agent never
calls another agent's client or service directly.

| User's input name | `AgentState` source | Notes |
|---|---|---|
| Alert | `alert_text`, `raw_alert` | Same fields `ThreatIntelAgent`/`MitreAgent` already read |
| Threat Intelligence Report | `iocs: list[Ioc]` | Current `AgentState` has no separate `ThreatIntelReport` type — `iocs` (per-IOC reputation/verdict data) *is* the threat intel report today |
| MITRE Mapping | `mitre_techniques: list[MitreTechniqueMatch]` | As written by `MitreAgent` |
| Playbook Context | `rag_result: RagAgentOutput` | Specifically `.context` (pre-formatted text block) and `.sources`; RagAgent's docstring confirms its Knowledge Base includes playbooks/SOPs/past incidents |
| Asset Information | **Gap — see below** | Not currently a field anywhere in `AgentState` or `apps/backend/prisma/schema.prisma` (no `Asset` model exists in the schema today) |

### Handling the Asset Information gap

Rather than block this design on a schema change to another agent's output
(out of scope — "do not modify the pipeline"), `context_assembler.py` (§5)
does a **best-effort, defensive extraction** from `raw_alert`, mirroring the
field-name-group technique `ioc_extractor.py` already uses for IOCs:

- hostname/host fields: `hostname`, `host`, `asset_name`, `device_name`
- identity fields: `src_ip`/`dst_ip` (already extracted as IOCs, cross-referenced not re-parsed), `user`, `owner`
- classification fields: `os`, `asset_type`, `criticality`, `environment` (prod/staging/etc.)

If none of these are present, `AnalysisContext.asset` is `None` — the prompt
and fallback template both say *"asset information not available"* rather
than inventing a plausible-sounding host. This is a stopgap, not a
replacement for a proper `asset_info` `AgentState` field; see §9 for the
recommended follow-up.

---

## 4. Output Contract

### New `AgentState` fields (additive — proposed)

```python
class LlmRootCause(TypedDict, total=False):
    hypothesis: str
    supportingEvidence: list[str]   # human-readable, each traceable to an input item
    confidence: Literal["low", "medium", "high"]

class LlmImpactAssessment(TypedDict, total=False):
    affectedAssets: list[str]
    scopeAssessment: str            # "contained" | "spreading" | "unknown", plus a sentence
    businessImpact: str
    severityRationale: str          # explains, never overrides, ml_risk_agent's severity_prediction

class LlmRecommendedAction(TypedDict, total=False):
    action: str
    priority: Literal["immediate", "high", "medium", "low"]
    rationale: str

class LlmAnalystOutput(TypedDict, total=False):
    incidentSummary: str
    rootCause: LlmRootCause
    impactAssessment: LlmImpactAssessment
    recommendedActions: list[LlmRecommendedAction]
    modelMeta: dict   # {model, generatedAt, degraded: bool, degradedReason: str | None}
```

```python
# AgentState additions
llm_analysis: LlmAnalystOutput
```

### Backward compatibility

`src/api/database.py:119-120` persists `state.get("llm_summary")` and
`state.get("llm_recommendation")`. Recommendation: **keep writing both**,
derived from the structured output —

```python
llm_summary = llm_analysis["incidentSummary"]
llm_recommendation = "; ".join(a["action"] for a in llm_analysis["recommendedActions"])
```

— so `database.py` needs no change on day one. Migrating persistence to store
`llm_analysis` as its own JSON column is a separate, explicit follow-up (§9),
not bundled into this agent's redesign.

---

## 5. Internal Architecture

Mirrors the layout already established by `rag_agent/` (`agent.py` +
`config.py` + `types.py` + single-purpose pure-function modules) — the most
recently built agent in this codebase and the closest fit for a Clean
Architecture split of orchestration vs. domain logic vs. infrastructure.

```
src/agents/llm_analyst_agent/
  __init__.py
  agent.py               # orchestration only — the LangGraph node entrypoint
  config.py               # this agent's own tunables (mirrors rag_agent/config.py)
  types.py                 # AnalysisContext, LlmRootCause, LlmImpactAssessment,
                            #   LlmRecommendedAction, LlmAnalystOutput — pure dataclasses
  context_assembler.py     # AgentState -> AnalysisContext   (pure, no I/O)
  prompts.py                # AnalysisContext -> (system_prompt, user_prompt)
  response_parser.py        # raw LLM text -> LlmAnalystOutput | raises ResponseParsingError
  fallback.py                # AnalysisContext -> LlmAnalystOutput (deterministic, no LLM)
  errors.py                   # ResponseParsingError
```

### Layer responsibilities (Clean Architecture mapping)

| Layer | Modules | Depends on |
|---|---|---|
| **Domain** | `types.py` | nothing (no framework, no I/O) |
| **Use case** | `agent.py` | domain types + the modules below, via function calls |
| **Application services** (pure, unit-testable in isolation) | `context_assembler.py`, `prompts.py`, `response_parser.py`, `fallback.py` | domain types only |
| **Interface adapter (gateway)** | `src/llm/provider_interface.py::ILlmProvider` | *already exists* — this agent depends only on the abstract interface, never a concrete provider |
| **Infrastructure** | `src/llm/llama_provider.py` | *already exists, unchanged* — swapping providers (OpenAI, vLLM, Anthropic) is a `config/settings.py` change, not a code change here |

Nothing under `llm_analyst_agent/` imports from `threat_intel_agent/`,
`mitre_agent/`, or `rag_agent/` — the only cross-agent contact point is
reading already-populated keys off `AgentState`, which is how every agent in
this pipeline talks to every other one. This import boundary is what makes
"must not query TI/MITRE/playbooks itself" a structural property, not just a
docstring promise.

---

## 6. Workflow / Data Flow

```
AgentState
    │
    ▼
context_assembler.assemble(state)                 — pure, sync, no I/O
    │  reads: alert_text, raw_alert, iocs, mitre_techniques,
    │         rag_result, risk_score/severity_prediction (if present),
    │         best-effort asset fields (§3)
    ▼
AnalysisContext
    │
    ▼
prompts.build(context)                             — pure
    │  → (system_prompt, user_prompt) requesting ONE strict-JSON response
    │    matching LlmAnalystOutput's shape; instructs the model to say
    │    "insufficient evidence" rather than speculate on any section
    ▼
(system_prompt, user_prompt)
    │
    ▼
llm_provider.complete(system_prompt, user_prompt)   — ILlmProvider, reused unchanged
    │
    ├── raises (unreachable / timeout / HTTP error) ──────────────┐
    │                                                              ▼
    ▼                                                     fallback.generate(context)
raw_text                                                           │
    │                                                              │
    ▼                                                              │
response_parser.parse(raw_text, context)                           │
    │  1. extract JSON (strip ```json fences if present)           │
    │  2. schema-validate required keys                            │
    │  3. grounding guard: strip any cited evidence not actually   │
    │     present in `context` (never trust an uncorroborated      │
    │     citation)                                                │
    │                                                              │
    ├── raises ResponseParsingError ──► retry once with a          │
    │        corrective prompt ──► still fails ─────────────────┐  │
    │                                                            ▼  ▼
    ▼                                                     fallback.generate(context)
LlmAnalystOutput  ◄─────────────────────────────────────────────┘
    │                            (merged: any section fallback
    │                             filled in keeps modelMeta.degraded=True
    │                             and a reason; sections the LLM did
    │                             produce validly are kept as-is)
    ▼
agent.run() maps result onto AgentState:
    { "llm_analysis": ..., "llm_summary": ..., "llm_recommendation": ...,
      "trace": [<one entry describing what happened>] }
```

### Why one LLM call instead of four (today's design uses two)

- **Consistency** — root cause and impact assessment should read the same
  evidence the same way; splitting into separate calls risks the two
  sections silently disagreeing (e.g. root cause says "contained to one
  host" while impact assessment says "spreading").
- **Latency/cost** — one round trip to the LLM endpoint instead of two–four.
- **Simpler failure surface** — one place to retry, one place to fall back,
  instead of coordinating partial failure across N independent calls.
- **Trade-off accepted**: parsing risk. A single structured-JSON response is
  more fragile to parse than four short plain-text completions. This is why
  §6 has an explicit parse-retry step and a grounding guard that today's
  agent doesn't need — the redesign's failure modes shift from "an LLM call
  failed" to "an LLM call failed *or* produced a response that doesn't parse
  cleanly," and both need to degrade the same way: never crash the graph,
  never fabricate.

---

## 7. Error Handling

| Failure | Detected by | Response |
|---|---|---|
| LLM endpoint unreachable (connection error, timeout, 5xx) | exception from `ILlmProvider.complete()` | No retry (retrying a dead endpoint just delays the analyst) — go straight to `fallback.generate()`. Trace: `"LlmAnalystAgent: LLM unavailable (<ExceptionType>), used fallback analysis"` |
| LLM response is not valid JSON | `json.JSONDecodeError` in `response_parser` | One bounded retry (`config.max_parse_retries`, default 1) with a corrective addendum ("your last response was not valid JSON — return ONLY valid JSON matching the schema"). Still fails → `fallback.generate()` |
| LLM JSON is missing a required top-level key | schema check in `response_parser` | Fill **only that section** from `fallback.generate()`; keep the sections that did parse. Matches today's per-field-independent fallback (`_fallback_summary` vs `_fallback_recommendation`), extended to four sections instead of two |
| LLM cites an IOC/technique/source not present in `AnalysisContext` | grounding guard cross-check | Strip the specific citation, keep the rest of the section, trace note. Never let an ungrounded claim reach the analyst silently — the whole point of feeding it real evidence is that its output should be traceable to that evidence |
| Context is thin (no IOCs, no MITRE matches, no RAG evidence, no asset) | `context_assembler` produces a mostly-empty `AnalysisContext` | Still call the LLM — a well-hedged "insufficient evidence to determine X" is a legitimate and useful output, not a failure. Prompt explicitly instructs this. `fallback.generate()` handles the all-empty case too |
| Any other unexpected exception anywhere in `run()` | top-level `try/except` in `agent.py` | Always resolves to `fallback.generate()` + trace note. `run()` itself never raises — same invariant every other node in this graph already holds |

`modelMeta.degraded` and `modelMeta.degradedReason` make every fallback
visible downstream (to `ValidationAgent`, to the analyst reading the
dashboard, to `docs/architecture` readers debugging a run) — degrade
silently in behavior, never silently in the audit trail.

---

## 8. Configuration Reference (proposed)

Mirrors `rag_agent/config.py`'s pattern of a small frozen dataclass loaded
from `settings.py`, kept separate from `Settings`' own connection config.

```python
@dataclass(frozen=True)
class LlmAnalystConfig:
    max_parse_retries: int = 1
    max_evidence_items: int = 10        # caps IOCs/techniques/RAG docs serialized into the prompt
    temperature: float = 0.2             # matches LlamaProvider's current hardcoded value
```

No new settings are strictly required to reuse `settings.llm_base_url` /
`settings.llm_model` / the existing `LlamaProvider`. `max_evidence_items`
exists for the same reason `ThreatIntelAgent` caps IOCs at 10 and `RagAgent`
caps `final_top_k` at 3 — bounding prompt size and cost regardless of how
much upstream evidence accumulated.

---

## 9. Open Questions / Follow-ups (not part of this design, flagged for decision)

1. **Asset Information has no home in `AgentState` or the DB schema.** The
   best-effort extraction in §3 is a stopgap. A proper fix is either a new
   `AssetEnrichmentAgent` upstream, or extending `ThreatIntelAgent`/alert
   ingestion to populate a dedicated `asset_info` field — out of scope here
   since it would touch other agents' contracts.
2. **Persistence**: whether `llm_analysis` gets its own column/JSON blob in
   `api/database.py::persist_agent_results`, or stays derived-only via
   `llm_summary`/`llm_recommendation` as described in §4, is a call for
   whoever owns the dashboard/API surface next.
3. **`ValidationAgent` currently doesn't check `LlmAnalystAgent`'s output**
   (`validation_agent/rules.py` only cross-checks TI/MITRE/MlRisk). Whether
   `modelMeta.degraded == True` should feed into `validate()` as a new rule
   (e.g. "flag for human review if the analysis was LLM-degraded") is worth
   deciding once this lands.
