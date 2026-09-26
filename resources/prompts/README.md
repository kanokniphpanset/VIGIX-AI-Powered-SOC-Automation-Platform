# Prompts

LLM prompt templates, one subfolder per agent. See the top-level
`resources/README.md` for the full "how to add a prompt" walkthrough and
the frontmatter format.

## `llm-analyst/`

Fully migrated (Phase 3) from `apps/ai-orchestrator/src/agents/llm_analyst_agent/prompts.py`,
which is now deleted. Four files, covering both LLM calls
`llm_analyst_agent/agent.py` makes:

| File | id | Used for |
|---|---|---|
| `summary-system.md` | `llm-analyst.summary.system` | System prompt for the alert-summary call. |
| `summary-user.md` | `llm-analyst.summary.user` | User-turn prompt (alert text, IOCs, MITRE techniques). |
| `recommendation-system.md` | `llm-analyst.recommendation.system` | System prompt for the next-actions-recommendation call. |
| `recommendation-user.md` | `llm-analyst.recommendation.user` | User-turn prompt (adds risk score, severity, retrieved knowledge-base evidence). |

Loaded via `apps/ai-orchestrator/resources/prompt_loader.py::PromptLoader`,
constructed once at module import time in `agent.py`
(`_prompts = PromptLoader()`).

## `rag-agent/`

Added in Phase D. Two files, covering the one LLM call
`rag_agent/agent.py` makes (to turn an already-retrieved, already-ranked
grounded context into a short analysis — RagAgent never uses an LLM for
retrieval, ranking, or the recommendations list itself, only for this
prose write-up):

| File | id | Used for |
|---|---|---|
| `assessment-system.md` | `rag-agent.analysis.system` | System prompt for the grounded-context analysis call. |
| `assessment-user.md` | `rag-agent.analysis.user` | User-turn prompt (investigation summary, MITRE context, retrieved knowledge/playbook text, known limitations). |

File names deliberately don't repeat the `analysis` word from their own
`id` — purely a naming choice made when these were added, no functional
significance (`id` is what `PromptLoader.get_by_id()`/`.render()` key off
of, never the filename).
