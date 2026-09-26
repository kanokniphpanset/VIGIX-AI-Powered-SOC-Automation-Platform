from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central config for the AI orchestrator. Every external dependency's
    connection info lives here so swapping providers is a config change,
    not a code change.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database (used to read alert context and persist agent results)
    database_url: str = "postgresql://soar:soar_password@localhost:5432/soar_platform"

    # Vector store
    qdrant_url: str = "http://localhost:6333"

    # Embeddings
    embedding_model: str = "BAAI/bge-small-en-v1.5"

    # LLM — pointed at an OpenAI-compatible endpoint (Ollama serves one by
    # default; a gateway like Bifrost that fronts multiple vLLM/llama.cpp
    # backends works the same way, just with a bearer token).
    llm_provider: str = "ollama"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_model: str = "llama3.1:8b-instruct-q4_K_M"
    # None for Ollama (no auth); set for a gateway that requires a bearer token.
    llm_api_key: str | None = None
    # CPU-only local inference genuinely takes longer than a typical HTTP
    # timeout — verified directly against a real Ollama instance on this
    # class of hardware: a trivial 2-token completion took ~90s. 30s (the
    # previous hardcoded value) meant the "real" LLM path could never
    # succeed here, only ever hit its timeout fallback.
    llm_timeout_seconds: float = 120.0

    # Threat intel (optional — agent degrades gracefully if unset). Every
    # provider's own is_configured gate handles "no key" — status becomes
    # NOT_CONFIGURED, never SUCCESS with fabricated data (see
    # threat_intel_agent/providers/).
    # Which providers the ThreatIntelAgent queries (comma-separated: virustotal, otx, misp, abuseipdb). A provider left
    # out is not called and not reported at all — use this to run only the providers you actually operate (e.g.
    # "misp" for a self-hosted MISP), instead of every unconfigured one being reported as NOT_CONFIGURED.
    threat_intel_providers: str = "virustotal,otx,misp,abuseipdb"

    misp_url: str | None = None
    misp_api_key: str | None = None
    misp_timeout: float = 10.0
    misp_verify_tls: bool = True

    virustotal_api_key: str | None = None
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    virustotal_timeout: float = 10.0

    otx_api_key: str | None = None
    otx_base_url: str = "https://otx.alienvault.com/api/v1/indicators"
    otx_timeout: float = 10.0

    abuseipdb_api_key: str | None = None
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    abuseipdb_timeout: float = 10.0

    # Retry/backoff (transient failures only — see providers/_http_base.py)
    threat_intel_retry_count: int = 2
    threat_intel_retry_backoff_seconds: float = 0.5

    # Redis-backed per-provider result cache (see cache.py). Same Redis
    # instance already provisioned in infra/docker/docker-compose.yml.
    redis_url: str = "redis://localhost:6379/0"
    threat_intel_cache_enabled: bool = True
    threat_intel_cache_ttl: int = 86400  # 24h, per spec default

    threat_intel_max_concurrency: int = 5
    threat_intel_max_iocs_per_alert: int = 25

    # Provider-specific rate limits (requests/minute across the whole
    # process, not per-call) — adjustable per operator's actual plan, never
    # hardcoded free/paid branching in code. 0 = unlimited. VirusTotal
    # defaults to 4/min (the public free-tier limit) as a safe starting
    # point; raise it if you have a paid key.
    virustotal_rate_limit_per_minute: int = 4
    otx_rate_limit_per_minute: int = 0
    misp_rate_limit_per_minute: int = 0
    abuseipdb_rate_limit_per_minute: int = 0

    # Backend — used to call back with the final decision so it can trigger n8n,
    # and (RagAgent) to reach the existing Vector Search Service at
    # POST /api/v1/knowledge/search — same backend_url, no second URL.
    backend_url: str = "http://localhost:4000"
    # Phase 5.8 — service-to-service credential for
    # POST /api/v1/webhooks/orchestrator/callback (see apps/backend's
    # orchestratorAuth.middleware.ts). Mint with
    # `npm run mint:orchestrator-token` in apps/backend. Empty by default —
    # notify_backend_of_decision() logs (not raises) if this is unset, the
    # same "don't fail the pipeline over a callback problem" contract it
    # already has for a failed HTTP call.
    backend_service_token: str = ""

    # RagAgent
    rag_top_k: int = 5
    rag_final_top_k: int = 3
    # See rag_agent/config.py::RagConfig.relevance_threshold for the
    # empirical evidence behind this default — 0.5 discarded every real
    # retrieval result regardless of relevance.
    rag_relevance_threshold: float = 0.35
    rag_vector_search_timeout_s: float = 10.0
    rag_vector_search_max_retries: int = 2
    # Phase D — dual retrieval (KNOWLEDGE vs PLAYBOOK collections), see
    # rag_agent/config.py::RagConfig for why these are independent knobs.
    rag_playbook_top_k: int = 5
    rag_playbook_final_top_k: int = 3

    # Decision policy — PolicyEngine reads these via SettingsPolicyConfigProvider
    # (decision_agent/policy_engine.py). Today: hardcoded/.env-backed defaults.
    # Later: swap the provider for a YAML- or database-backed one without
    # PolicyEngine or any individual policy function changing.
    risk_auto_response_threshold: float = 30.0
    risk_human_approval_threshold: float = 70.0
    decision_confidence_floor: float = 0.6
    decision_policy_registry_version: str = "policy-registry@v1"
    decision_result_expiration_minutes: int = 30

    # Emergency Override Policy (Tier 0) — an absolute, temporary override for
    # declared incidents. `emergency_override_outcome` must be one of
    # "dismiss" | "auto_response" | "human_approval" | "escalate".
    emergency_override_active: bool = False
    emergency_override_outcome: str = "escalate"

    # Time Window Policy (Tier 8) — set true during a declared change freeze.
    change_freeze_active: bool = False

    # Jira notification — human-in-the-loop approval tickets, opened when
    # DecisionAgent's output is HUMAN_APPROVAL_REQUIRED (see
    # notifications/jira_notification_service.py). Notification only: Jira
    # never influences the decision itself. Mock mode (the default) never
    # calls the real Jira API, so the human-approval demo works without a
    # Jira account.
    jira_enabled: bool = False
    jira_mock_mode: bool = True
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str = "SEC"
    jira_issue_type: str = "Task"
    jira_timeout_s: float = 10.0

    # Email notification — SMTP. Notification only, same as Teams/LINE below;
    # never influences the decision itself.
    email_enabled: bool = False
    email_mock_mode: bool = True
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    email_from: str | None = None
    soc_email: str | None = None
    email_timeout_s: float = 10.0

    # Microsoft Teams notification — Incoming Webhook.
    teams_enabled: bool = False
    teams_mock_mode: bool = True
    teams_webhook_url: str | None = None
    teams_timeout_s: float = 10.0

    # LINE notification — LINE Messaging API (push message). LINE Notify is
    # discontinued; deliberately not implemented.
    line_enabled: bool = False
    line_mock_mode: bool = True
    line_channel_access_token: str | None = None
    line_target_id: str | None = None
    line_timeout_s: float = 10.0

    # NotificationPolicy tunables — read via SettingsNotificationPolicyConfigProvider
    # (notifications/notification_policy.py). Comma-separated.
    notification_urgent_priorities: str = "P1"
    notification_high_severity_values: str = "high,critical"

    # Server
    api_port: int = 8000


settings = Settings()
