"""Output schema of the threat intel agent."""
from __future__ import annotations

from src.schemas.threat_intel import SourceVerdict, ThreatIntelResult  # shared schema

__all__ = ["SourceVerdict", "ThreatIntelResult"]
