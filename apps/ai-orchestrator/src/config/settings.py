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
    misp_url: str | None = None
    misp_api_key: str | None = None
    virustotal_api_key: str | None = None
    otx_api_key: str | None = None

    # Backend — used to call back with the final decision so it can trigger n8n
    backend_url: str = "http://localhost:4000"

    # Decision policy
    risk_auto_response_threshold: float = 30.0
    risk_human_approval_threshold: float = 70.0

    # Server
    api_port: int = 8000


settings = Settings()
