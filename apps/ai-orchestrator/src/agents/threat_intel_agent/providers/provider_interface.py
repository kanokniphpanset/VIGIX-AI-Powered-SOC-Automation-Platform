"""
Abstract Threat Intelligence provider — mirrors the ABC pattern already used
by llm/provider_interface.py::ILlmProvider, vectorstore/provider_interface.py
::IVectorStore, and ml_models/provider_interface.py::IRiskModel. ThreatIntel
Agent depends only on this; add a new provider (Recorded Future, Shodan, ...)
by adding a class here and wiring it into agent.py's provider list — nothing
else in the agent changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..types import IocType, ThreatIntelProviderResult


class ThreatIntelProvider(ABC):
    """
    name        — human-readable provider name, used in ThreatIntelData.sources
                  and structured logs. Must never be, or contain, a secret.
    is_configured — False when required config (API key/URL) is absent. The
                  agent checks this before calling analyze() and never treats
                  an unconfigured provider as a hard failure.
    supports()  — whether this provider has a meaningful lookup for the given
                  IOC type. AbuseIPDB, for example, only supports IP addresses.
    analyze()   — perform the lookup and return a normalized result. Must
                  never raise for expected failure modes (timeout, 4xx/5xx,
                  malformed response) — those are caught internally and
                  reflected in the returned ProviderStatus. It's expected to
                  raise only for truly unexpected programming errors.
    """

    name: str

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def supports(self, ioc_type: IocType) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def analyze(self, indicator: str, ioc_type: IocType) -> ThreatIntelProviderResult:
        raise NotImplementedError
