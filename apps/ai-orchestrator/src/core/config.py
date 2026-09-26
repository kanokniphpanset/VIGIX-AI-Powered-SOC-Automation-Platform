"""Settings read from environment variables. No secret is hard-coded here."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    wazuh_indexer_url: str = ""
    wazuh_indexer_user: str = ""
    wazuh_indexer_password: str = ""
    qdrant_url: str = ""
    database_url: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    llm_model: str = ""
    analyst_prompt_version: str = "v1.0"
    recommendation_prompt_version: str = "v1.0"

    @classmethod
    def from_env(cls) -> "Settings":
        g = os.environ.get
        return cls(
            wazuh_indexer_url=g("WAZUH_INDEXER_URL", ""), wazuh_indexer_user=g("WAZUH_INDEXER_USER", ""),
            wazuh_indexer_password=g("WAZUH_INDEXER_PASSWORD", ""), qdrant_url=g("QDRANT_URL", ""),
            database_url=g("DATABASE_URL", ""), virustotal_api_key=g("VIRUSTOTAL_API_KEY", ""),
            abuseipdb_api_key=g("ABUSEIPDB_API_KEY", ""), otx_api_key=g("OTX_API_KEY", ""),
            misp_url=g("MISP_URL", ""), misp_api_key=g("MISP_API_KEY", ""), llm_model=g("LLM_MODEL", ""),
            analyst_prompt_version=g("ANALYST_PROMPT_VERSION", "v1.0"),
            recommendation_prompt_version=g("RECOMMENDATION_PROMPT_VERSION", "v1.0"),
        )
