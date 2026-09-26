---
id: llm-analyst.recommendation.user
version: "2"
variables: [alert_text, iocs, mitre_techniques, risk_score, severity_prediction, risk_confidence, risk_model, rag_context]
description: User-turn prompt handing the alert, IOCs, MITRE mapping, risk score, and retrieved knowledge-base evidence to the LLM for a recommendation.
---
Alert: {alert_text}

IOCs: {iocs}
MITRE techniques: {mitre_techniques}
ML Risk (already computed — treat as authoritative, do not recalculate): score={risk_score}, level={severity_prediction}, confidence={risk_confidence}, model={risk_model}
Relevant knowledge base evidence (playbooks, SOPs, past incidents):
{rag_context}
