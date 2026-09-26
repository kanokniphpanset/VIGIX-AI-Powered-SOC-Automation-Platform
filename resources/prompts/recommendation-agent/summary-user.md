---
id: recommendation-agent.summary.user
version: "1"
variables: [incident_type, classification_confidence, recommendation_titles, missing_evidence, alert_text]
description: User prompt template supplying the classified incident type, confidence, selected recommendation titles, and withheld/missing-evidence entries for RecommendationAgent's investigation summary call.
---
Alert:
{alert_text}

Classified incident type: {incident_type} (confidence: {classification_confidence})

Recommendations already selected (category: title):
{recommendation_titles}

Recommendations withheld for missing evidence:
{missing_evidence}

Write the investigation summary now.
