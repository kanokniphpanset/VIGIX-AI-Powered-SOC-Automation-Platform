---
id: rag-agent.analysis.user
version: "1"
variables: [investigation_summary, knowledge_context, playbook_context, mitre_context, limitations]
description: User-turn prompt handing the grounded investigation summary, retrieved knowledge base evidence, and retrieved playbook evidence to the LLM for analysis.
---
Investigation summary: {investigation_summary}

MITRE techniques observed: {mitre_context}

Retrieved knowledge base evidence:
{knowledge_context}

Retrieved playbook evidence:
{playbook_context}

Known limitations of this retrieval (state these explicitly if relevant, do not try to fill the gap): {limitations}
