from src.graph.state import AgentState
from .attack_matrix import ATTACK_MATRIX


async def run(state: AgentState) -> AgentState:
    """
    MitreAgent — maps alert text onto MITRE ATT&CK techniques via keyword
    matching against attack_matrix.py. Confidence is proportional to how many
    of a technique's keywords appear in the alert (crude but transparent —
    every match is explainable, which matters for an analyst auditing the call).
    """
    text = state.get("alert_text", "").lower()

    matches = []
    for technique in ATTACK_MATRIX:
        hits = [kw for kw in technique["keywords"] if kw in text]
        if hits:
            confidence = min(1.0, 0.4 + 0.2 * len(hits))
            matches.append(
                {
                    "technique_id": technique["technique_id"],
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "confidence": round(confidence, 2),
                }
            )

    matches.sort(key=lambda m: m["confidence"], reverse=True)

    return {"mitre_techniques": matches, "trace": [f"MitreAgent: matched {len(matches)} technique(s)"]}
