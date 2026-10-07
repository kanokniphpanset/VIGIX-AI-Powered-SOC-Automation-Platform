# Corrections to earlier statements

The frozen result files are **not edited** (their hashes are part of `frozen-manifest.json`). Where an earlier statement of mine turned out to be wrong, the correction is recorded here and in `paper-metrics.json` (`corrections`).

## C1 — Which LLM produced the results (found during this task)

| | |
|---|---|
| Earlier statement | "LLM: provider `openrouter`, model `google/gemma-4-26b-a4b-it`" — described as an assumption because `LLM_PROVIDER` is defined twice in `apps/ai-orchestrator/.env`. Appears in `results/findings-and-limitations.md`, `results/evaluation-summary.md`, `results/evaluation-audit.md` and `results/runs/*/run.json` (`preflight.env.llm`), and in my earlier chat summaries. |
| Verified fact | The orchestrator's analysis and recommendation calls use `LlamaProvider(settings.llm_base_url, settings.llm_model, …)` only (`apps/ai-orchestrator/src/api/routes/recommendations.py`, `agents/llm_analyst_agent/agent.py`, `config/settings.py`); there is no OpenRouter branch on that path. The model recorded in **all 19** `llm_analyst` results of the frozen database is **`vllm-spark-01/gemma4-26b-uncensored`**, served by a self-hosted OpenAI-compatible vLLM endpoint; the string `google/gemma` occurs in none of them. |
| How it surfaced | During the consistency run that endpoint became unreachable (`LLM_TIMEOUT`, then `ConnectError`), which cannot happen to OpenRouter while `openrouter.ai` answered HTTP 200; after it returned the runs completed. |
| Effect on numbers | None. No metric was computed from the provider name; only the description of the environment (and of who operates the model) changes. Papers should cite `vllm-spark-01/gemma4-26b-uncensored` (self-hosted vLLM). |

## C2 — Negative scenario NEG-02: layer expectation
I expected the "required evidence type absent" scenario to be rejected at the **Policy** layer. The recorded violation (`INSUFFICIENT_EVIDENCE`, COMMAND_LINE for `ACT-KILL-PROCESS`) carries no `POL-A0x` policy name: the requirement comes from the Action's own knowledge, so it is a **validator-layer** rejection. The rejection occurred (10/10); only my expectation of the layer was wrong. The tables show both the expectation and the actual layer; the Policy-derived rejections are NEG-03 (responsible role) and NEG-04 (approval waiver).

## C3 — Consistency of TC-09
The first TC-09 attempt produced five `AI_UNAVAILABLE` failures (LLM endpoint timeout / connection error). They were **not** reported as 0% consistency: all attempt files are kept, the failures are listed as infrastructure failures, and TC-09 was repeated once the endpoint answered again.
