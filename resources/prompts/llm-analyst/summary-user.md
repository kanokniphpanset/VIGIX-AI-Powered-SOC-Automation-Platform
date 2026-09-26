---
id: llm-analyst.summary.user
version: "1"
variables: [alert_text, iocs, mitre_techniques]
description: User-turn prompt handing the alert, extracted IOCs, and MITRE technique matches to the LLM for summarization.
---
Alert: {alert_text}

IOCs found: {iocs}
MITRE techniques: {mitre_techniques}
