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

    # LLM — pointed at an OpenAI-compatible endpoint (Ollama serves one by default)
    llm_provider: str = "ollama"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_model: str = "llama3.1:8b-instruct-q4_K_M"

    # Threat intel (optional — agent degrades gracefully if unset)
    threat_intel_enabled: bool = True

    misp_url: str | None = None
    misp_api_key: str | None = None
    misp_timeout: float = 5.0
    # MISP instances are frequently self-signed in lab/on-prem deployments; default
    # to strict verification and let operators explicitly opt out per-instance.
    misp_verify_tls: bool = True

    virustotal_api_key: str | None = None
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    virustotal_timeout: float = 5.0

    abuseipdb_api_key: str | None = None
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    abuseipdb_timeout: float = 5.0

    otx_api_key: str | None = None
    otx_base_url: str = "https://otx.alienvault.com/api/v1/indicators"
    otx_timeout: float = 5.0

    # Cross-provider IOC enrichment behavior
    threat_intel_cache_enabled: bool = True
    threat_intel_cache_ttl: int = 3600  # seconds
    threat_intel_max_concurrency: int = 3
    threat_intel_retry_count: int = 2
    threat_intel_retry_backoff_seconds: float = 0.5
    threat_intel_max_iocs_per_alert: int = 25

    # Decision policy
    risk_auto_response_threshold: float = 30.0
    risk_human_approval_threshold: float = 70.0

    # Server
    api_port: int = 8000


settings = Settings()
