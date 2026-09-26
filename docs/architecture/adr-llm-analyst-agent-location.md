# ADR: Where LlmAnalystAgent Should Live

**Status:** Accepted
**Decision:** Implement/extend `LlmAnalystAgent` inside `apps/ai-orchestrator/src/agents/llm_analyst_agent/` (Python, LangGraph node). Do **not** create a second implementation in `apps/backend` (TypeScript).

This document is the architecture-only counterpart to
[`llm-analyst-agent.md`](llm-analyst-agent.md) (the agent's internal module
design, already written assuming a Python location). That doc's "Status:
design only" is unaffected by this ADR — this ADR confirms *where* that
design should be built, not what it contains.

An earlier working session in this repository explored a parallel
TypeScript implementation (`models.ts`, `prompt_builder.ts`, `agent.ts`,
`recommendation.ts`, `report_builder.ts`) as a Clean-Architecture exercise.
**None of those files were ever written to disk** — they exist only as chat
output. This ADR formally supersedes that direction: it is not to be
implemented as a second production agent. The ideas in it that are still
useful (the Zod-schema-shaped output contract, the citation-grounding
validation strategy, the multi-consumer report-shaping approach) should
inform the *Python* implementation instead, per §5.

---

## 1. Current Repository Structure

### `apps/backend` (TypeScript)

Clean Architecture, four rings: `domain/`, `application/`, `infrastructure/`,
`presentation/`, plus `shared/`. Dependency injection is manual constructor
injection wired in one composition root, `infrastructure/config/container.ts`
— no DI framework/decorators.

Confirmed responsibilities today:
- REST API (Express-style controllers in `presentation/http/`)
- SIEM alert ingestion (`SiemInboundWebhookController` → `IngestAlertFromSiemUseCase`)
- Incident CRUD/timeline (`IncidentController`)
- **Ad-hoc** threat-intel lookup (`AnalyzeIndicatorUseCase`) — deterministic scoring (`ThreatScoringService`), explicitly **not** LLM-based (see `AnalyzeIndicatorResultDto`'s own comment: *"Deterministic, rule-based narrative... NOT a live LLM call"*)
- MITRE technique mapping (`MapAlertToMitreOutputUseCase`) — rule/keyword-based (`BehaviorExtractorService`, `TechniqueMapperService`), also not LLM-based
- Knowledge Base ingestion + embedding pipeline (MITRE STIX, internal docs, MISP sync) and a **read-only vector search HTTP service** (`QdrantVectorSearchService` / `KnowledgeSearchController`) that the orchestrator's RagAgent calls into
- Dispatching pipeline runs to the orchestrator (`IAiOrchestratorPort` → `LangGraphOrchestratorAdapter`)
- Receiving the orchestrator's decision callback and triggering n8n (`OrchestratorCallbackController` → `IWorkflowEnginePort`)

**No LLM client, LLM port, or LLM-shaped abstraction exists anywhere in
`apps/backend/src` today.** This is not an oversight — two separate modules
(threat-intel scoring, MITRE mapping) were deliberately kept deterministic
and rule-based specifically so the backend never needs an LLM dependency.

### `apps/ai-orchestrator` (Python + FastAPI + LangGraph)

```
src/
  agents/{threat_intel_agent, mitre_agent, rag_agent, ml_risk_agent,
           llm_analyst_agent, validation_agent, decision_agent,
           business_analytics_agent, feedback_agent}/
  graph/{state.py, build_graph.py, router.py}
  llm/{provider_interface.py, llama_provider.py}
  embeddings/, vectorstore/, ml_models/, tools/
  config/settings.py
  api/{routes/, database.py, backend_client.py, schemas.py}
```

FastAPI exposes exactly two routers: `/pipeline` (`run_pipeline.py`) and
`/embeddings`. Everything else in this service exists to support the
LangGraph pipeline.

### Existing AI Agents (all in `apps/ai-orchestrator`)

| Agent | Role |
|---|---|
| `threat_intel_agent` | Extracts IOCs, queries VirusTotal/OTX/MISP |
| `mitre_agent` | Keyword-matches alert text to ATT&CK techniques |
| `rag_agent` | Retrieves/re-ranks Knowledge Base evidence (playbooks/SOPs/past incidents) via the backend's vector-search HTTP endpoint |
| `ml_risk_agent` | Computes `risk_score`/`severity_prediction`/`confidence_score` |
| **`llm_analyst_agent`** | **Already exists.** Calls an LLM (`ILlmProvider`/`LlamaProvider`, OpenAI-compatible endpoint) for a summary + recommendation, with a deterministic fallback if the LLM is unreachable |
| `validation_agent` | Rule-based cross-checks of the above agents' outputs; can trigger a retry |
| `decision_agent` | auto_response / human_approval / dismiss |
| `business_analytics_agent` | KPI snapshotting |
| `feedback_agent` | Logs outcome for retraining |

`llm_analyst_agent` is not hypothetical — it is a working LangGraph node
today, already depending on `ILlmProvider` (an abstract interface,
`src/llm/provider_interface.py`) rather than a concrete provider, with
`LlamaProvider` as the current adapter. That is precisely the Dependency
Inversion seam the richer 4-responsibility design needs — it already exists,
in Python.

---

## 2. Current AI Pipeline

```
SIEM → POST /webhooks/siem/:source (backend)
         → IngestAlertFromSiemUseCase saves the alert (shared Postgres)
         → IAiOrchestratorPort.dispatch() → LangGraphOrchestratorAdapter
            → POST {AI_ORCHESTRATOR_URL}/pipeline/run   [backend → orchestrator, HTTP]

ai-orchestrator: POST /pipeline/run  (src/api/routes/run_pipeline.py)
  1. fetch_alert()               — reads the alert row directly from Postgres
                                    via psycopg (NOT via a backend API call —
                                    backend and orchestrator share one database)
  2. ensure_incident_for_alert() / create_agent_execution()
  3. build initial AgentState (alert_id, tenant_id, raw_alert, alert_text, ...)
  4. await compiled_graph.ainvoke(initial_state)     — the LangGraph run:

       START → threat_intel → mitre → rag → ml_risk → llm_analyst → validation
                                                                        │
                                        ┌── retry (validation failed) ──┘
                                        │        (loops back to threat_intel,
                                        │         up to a retry cap)
                                        └── proceed → decision_agent
                                                          → business_analytics
                                                          → feedback → END

       (mid-graph: rag_agent makes ONE synchronous HTTP call OUT to the
        backend's POST /api/v1/knowledge/search — the only agent that talks
        to the backend during the run)

  5. persist_agent_results()     — writes every agent's output to Postgres
  6. notify_backend_of_decision() → POST {backend_url}/webhooks/orchestrator/callback
  7. returns the full result synchronously to the original dispatch call
```

`OrchestratorCallbackController` (backend) receives step 6, and — unless the
decision is `"dismiss"` — calls `IWorkflowEnginePort.triggerPlaybook()` to
fire the n8n workflow (Teams notification, ticket creation).

**Key facts this ADR relies on:**
- The whole graph runs as **one atomic in-process call** (`ainvoke`) — there is no per-node network hop between orchestrator agents.
- `AgentState` (`src/graph/state.py`) is the single shared contract every node reads/writes; nothing crosses agents any other way.
- The validation→retry loop (`graph/router.py::after_validation`) only works because every node, including `llm_analyst`, participates in the same compiled graph.
- Backend and orchestrator already share one Postgres database directly — the orchestrator does not go through the backend's API to read its own alert data.
- The backend↔orchestrator boundary today is exactly two calls per pipeline run: one dispatch in, one decision callback out (plus RagAgent's one mid-graph vector-search call). It carries **no AI reasoning**, only pipeline control and a decision result.

---

## 3. Recommended Location

**`apps/ai-orchestrator/src/agents/llm_analyst_agent/`** — extend the
existing module, do not build a parallel implementation elsewhere.

| Criterion | Assessment |
|---|---|
| **Maintainability** | One codebase already owns "call an LLM for this alert" (`ILlmProvider`/`LlamaProvider`, `settings.llm_base_url`/`llm_model`). A second, TS-based LLM integration would mean two prompt files, two config surfaces, two places a prompt-injection fix or a schema change has to land — and no guarantee they'd land in both. |
| **Scalability** | LangGraph already sequences/parallelizes agent execution in one process with `asyncio`. Moving this one node out to an HTTP call into the backend mid-graph adds a network hop, a new timeout/failure mode, and breaks the graph's in-process state semantics (see the retry-loop point in §2) for no throughput benefit — nothing about "call an LLM" requires being in a different process from the graph that orchestrates it. |
| **Separation of concerns** | The codebase has already drawn this line twice on purpose: threat-intel scoring and MITRE mapping are both kept in the backend specifically as **deterministic, non-LLM** logic, explicitly commented as such. LlmAnalystAgent is the one genuinely LLM-driven reasoning step in the pipeline — putting it in the backend would be the first violation of a boundary the team has otherwise held consistently. |
| **Production readiness** | The orchestrator's `llm_analyst_agent` is already a working, wired LangGraph node with a working degrade-on-unreachable-LLM fallback. Extending it to four structured sections is additive. A TS twin would have to re-solve JSON-mode prompting, retry-on-malformed-response, and graceful degradation from zero, in a second language, on a second config surface. |
| **Consistency with existing architecture** | Every other reasoning-shaped step in the sequential chain that feeds `llm_analyst` (ThreatIntel scoring, MITRE matching, RAG retrieval/rerank, ML risk scoring) already lives in the orchestrator. `llm_analyst` is the 5th node reading the first four's output out of `AgentState` — architecturally it is just another LangGraph node in an existing chain, not a new category of component that would justify living in a different service. |

**Conclusion matches the expected recommendation**: since the current
architecture already executes every AI agent in `apps/ai-orchestrator`,
`LlmAnalystAgent` belongs there too — extending code and a wiring point that
already exist, not creating a second one.

---

## 4. Integration Plan (LangGraph)

**No graph topology change is needed** — the node already exists and is
already correctly positioned.

| Aspect | Current state (unchanged by this work) |
|---|---|
| Node name | `"llm_analyst"` (`build_graph.py:43`) |
| Previous node | `ml_risk` — edge `ml_risk → llm_analyst` already exists (`build_graph.py:60`) |
| Next node | `validation` — edge `llm_analyst → validation` already exists (`build_graph.py:61`) |

What actually changes is internal to the node, not its place in the graph:

- **State input**: same fields already read today (`alert_text`, `raw_alert`, `iocs`, `mitre_techniques`, `rag_result`), plus a best-effort extraction of asset fields from `raw_alert` (no dedicated `asset_info` field exists yet in `AgentState` — a known gap, see `llm-analyst-agent.md` §3). `risk_score`/`severity_prediction`/`confidence_score` remain available as optional context since `ml_risk` runs immediately before this node.
- **State output**: today's `llm_summary`/`llm_recommendation` (kept, derived) plus a new structured key, `llm_analysis`, added to `AgentState` (`src/graph/state.py`) — same pattern already used for every other agent's output (`RagAgentOutput`, `MitreTechniqueMatch`, etc. all live inline in that file).
- **Shared models**: `AgentState` remains the *only* shared contract — no new cross-agent model file is introduced; the new `LlmAnalystOutput`/`LlmRootCause`/`LlmImpactAssessment`/`LlmRecommendedAction` TypedDicts are added to `state.py` alongside the existing ones.
- **Prompt flow**: system + user prompt built by `prompts.py` (extended to the 4-section structured-JSON design), sent through the **existing** `ILlmProvider.complete()` / `LlamaProvider`. No new LLM client and no new provider abstraction — the seam already supports swapping providers via config alone.

---

## 5. Required Files

No code is included below, per the constraint. Paths mirror the module
design already specified in `llm-analyst-agent.md` §5.

**New files** (`apps/ai-orchestrator/src/agents/llm_analyst_agent/`):
- `types.py`
- `context_assembler.py`
- `response_parser.py`
- `fallback.py`
- `config.py`
- `errors.py`

**New test files** (`apps/ai-orchestrator/tests/agents/llm_analyst_agent/`),
mirroring the module-per-file test convention already used elsewhere in
this repo (e.g. `tests/agents/threat_intel_agent/`).

**Modified files:**
- `apps/ai-orchestrator/src/agents/llm_analyst_agent/agent.py` — rewrite `run()` to orchestrate the new modules instead of two flat LLM calls
- `apps/ai-orchestrator/src/agents/llm_analyst_agent/prompts.py` — extend to the 4-section structured-JSON prompt
- `apps/ai-orchestrator/src/graph/state.py` — add `llm_analysis` and its sub-types to `AgentState`
- `apps/ai-orchestrator/src/config/settings.py` — only if new tunables are exposed as env vars rather than `config.py` defaults (e.g. `max_evidence_items`, `max_parse_retries`)
- `apps/ai-orchestrator/src/api/database.py` — only if `llm_analysis` gets its own persisted column (optional follow-up, not required for day one — see `llm-analyst-agent.md` §9)
- `apps/ai-orchestrator/tests/graph/test_build_graph.py` — verify/extend, since it currently asserts on `llm_summary`/`llm_recommendation`
- `docs/architecture/llm-analyst-agent.md` — flip its status line from "design only" to "implemented" once this lands

**Explicitly NOT required — and explicitly prevented by this decision:**
Nothing under `apps/backend/src`. No `models.ts`, `prompt_builder.ts`,
`agent.ts`, `recommendation.ts`, `report_builder.ts`. No new
`container.ts` wiring, no new controller/route. The backend needs zero code
changes for this work.

---

## 6. Risks

- **Duplicated implementation** — the risk this ADR exists to prevent. Two independent "ask an LLM to analyze this incident" code paths (Python in the orchestrator, TS in the backend) would mean two prompts, two output schemas, two failure-handling strategies that can silently drift (e.g. an anti-hallucination fix landing in one and not the other).
- **Inconsistent pipeline** — `AgentState` is the single source of truth threaded through 9 in-process nodes. A TS implementation living outside the graph would need its own state-passing mechanism (HTTP payloads to/from the backend), and any future change to what `MitreAgent`/`RagAgent` write to `AgentState` would require updating two independent consumers instead of one.
- **Duplicated LLM calls** — without one call site, a future backend feature could end up invoking its own analysis for the same alert, doubling LLM cost and producing two summaries with no clear "which one is authoritative" answer for the analyst.
- **Maintenance burden** — two prompt files, two JSON schemas, two grounding/anti-hallucination implementations, two on-call runbooks, two places a security fix has to land.
- **Retry-loop incompatibility** — the validation→retry edge (`graph/router.py::after_validation`, looping back to `threat_intel` up to a retry cap) only works inside the compiled graph's single invocation. An out-of-process TS implementation sits outside that loop entirely and cannot participate in a validation-triggered re-run without new cross-service retry plumbing that doesn't exist today.
- **Pre-existing coupling worth noting (not introduced by this decision)** — the orchestrator already reads/writes the shared Postgres database directly rather than through the backend's API. This is a pre-existing architectural characteristic, not something this ADR changes, but it reinforces that orchestrator-side logic already assumes direct access to shared state — consistent with keeping `LlmAnalystAgent` there too.

---

## 7. Migration Strategy

This is an **in-place extension** of an already-wired node, not a
cross-service migration — no code needs to move, and the graph topology
does not change.

1. Add the new Python modules (`types.py`, `context_assembler.py`,
   `fallback.py`, `errors.py`, `config.py`) as pure additive scaffolding —
   no behavior change, doesn't touch `agent.py`'s current `run()` or the
   graph.
2. Extend `AgentState` additively — add `llm_analysis` and its sub-types
   alongside the existing `llm_summary`/`llm_recommendation` keys, so every
   current reader of those two keys (`api/database.py`,
   `tests/graph/test_build_graph.py`) keeps working unmodified.
3. Extend `prompts.py` to request the 4-section structured-JSON output,
   behind the same `ILlmProvider.complete()` call already in place — no new
   LLM client, no new required settings to ship a first version.
4. Rewrite `agent.py`'s `run()` to call the new
   `context_assembler → prompts → ILlmProvider → response_parser → fallback`
   chain, populating `llm_analysis` while still deriving
   `llm_summary`/`llm_recommendation` from it for backward compatibility.
   This is the one behavior-changing step, isolated to a single file.
5. Run the existing and new test suites
   (`tests/agents/llm_analyst_agent/`, `tests/graph/test_build_graph.py`)
   before merging. No test changes are needed for graph wiring, since node
   topology is untouched.
6. Optional staged rollout: since `run()` already degrades gracefully on
   any LLM/parsing failure, shipping directly is safe — but a config toggle
   (e.g. `settings.llm_analyst_structured_output_enabled`) could gate the
   new prompt shape during a canary period if a staged rollout is
   preferred.
7. Once stable, flip `llm-analyst-agent.md`'s status line from "design
   only" to "implemented."
8. **Backend requires zero code changes.** It only dispatches and receives
   a callback today; exposing the richer `llm_analysis` payload through a
   new backend read-model (e.g. for the dashboard) is a separate, later
   decision — not part of this migration.

---

## Success Criteria (confirmed against the request)

- Architecture only — no code included above. ✔
- No TypeScript implementation introduced or recommended. ✔
- No duplicate AI agents — the earlier TS exploration is explicitly
  superseded, and confirmed never written to disk. ✔
- Compatible with the existing LangGraph workflow — zero topology changes,
  reuses the existing node, edges, `AgentState`, and `ILlmProvider` seam. ✔
- Ready for implementation in the next step — §5–§7 give an exact file list
  and a sequenced, backward-compatible rollout plan.
