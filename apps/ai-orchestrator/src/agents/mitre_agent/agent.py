"""MITRE ATT&CK mapping agent — LangGraph node.

Maps observed alert behaviour to catalog-validated MITRE ATT&CK techniques.
"""

from __future__ import annotations

from src.config.settings import settings
from src.contracts.error_builder import build_error
from src.graph.state import AgentState

from .behavior_extractor import BehaviorExtractor
from .knowledge_base_client import MitreKnowledgeBaseClient
from .technique_mapper import TechniqueMapper


_kb_client: MitreKnowledgeBaseClient | None = None
_mapper: TechniqueMapper | None = None
_extractor: BehaviorExtractor | None = None


def _get_components() -> tuple[BehaviorExtractor, TechniqueMapper]:
    global _kb_client, _mapper, _extractor

    if _kb_client is None:
        _kb_client = MitreKnowledgeBaseClient(settings.backend_url)

    if _mapper is None:
        _mapper = TechniqueMapper(_kb_client)

    if _extractor is None:
        _extractor = BehaviorExtractor()

    return _extractor, _mapper


async def run(state: AgentState) -> AgentState:
    """LangGraph MITRE mapping node."""

    try:
        extractor, mapper = _get_components()

        raw_alert = state.get("raw_alert") or {}
        alert_text = state.get("alert_text", "")
        threat_intel_report = state.get("threat_intel_report") or {}

        signals = extractor.extract(
            alert_text=alert_text,
            raw_alert=raw_alert,
            threat_intel_report=threat_intel_report,
        )

        # Wazuh's own rule.mitre.id is authoritative: when the alert carries it, only those
        # techniques are mapped. Keyword inference is a fallback for alerts without Wazuh MITRE.
        native = [s for s in signals if s.category.startswith("NATIVE_MITRE:")]
        mapped = await mapper.map_signals(native) if native else []
        mitre_source = "WAZUH"
        # No Wazuh tag, or one the MITRE catalog rejected: fall back to inference from the alert text.
        if not mapped:
            mapped = await mapper.map_signals([s for s in signals if s not in native])
            mitre_source = "AI_INFERRED" if mapped else "NONE"

        techniques = [technique.to_dict() for technique in mapped]

        result = "MAPPED" if techniques else "NO_SUPPORTED_MAPPING"

        report = {
            "result": result,
            "mitreSource": mitre_source,
            "techniques": techniques,
            "signalCount": len(signals),
            "techniqueCount": len(techniques),
        }

        return {
            "mitre_techniques": techniques,
            "mitre_mapping_report": report,
            "trace": [
                f"MitreAgent: extracted {len(signals)} signal(s), "
                f"mapped {len(techniques)} technique(s)"
            ],
        }

    except Exception as exc:
        error = build_error(
            agent="mitre",
            code="AGENT_EXECUTION_FAILED",
            message=f"MITRE agent failed: {exc}",
            retryable=True,
            severity="ERROR",
        )

        return {
            "mitre_techniques": [],
            "mitre_mapping_report": {
                "result": "ERROR",
                "techniques": [],
            },
            "structured_errors": [
                error.model_dump(by_alias=True, mode="json")
            ],
            "trace": [
                f"MitreAgent: execution failed ({type(exc).__name__})"
            ],
        }
