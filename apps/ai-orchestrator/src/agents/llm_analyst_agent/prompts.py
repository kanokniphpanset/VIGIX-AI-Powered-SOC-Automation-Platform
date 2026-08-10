SUMMARY_SYSTEM_PROMPT = """You are a SOC analyst assistant. Summarize the security alert factually \
in 2-3 sentences. Do not speculate beyond the evidence given. Do not include recommendations here."""

RECOMMENDATION_SYSTEM_PROMPT = """You are a SOC analyst assistant. Given the alert, threat intelligence, \
MITRE ATT&CK mapping, and risk score below, recommend 2-4 concrete next actions for the analyst. \
Be specific and operational (e.g. 'isolate host X', 'reset credentials for user Y'), not generic advice."""


def build_summary_prompt(state: dict) -> str:
    return (
        f"Alert: {state.get('alert_text', '')}\n\n"
        f"IOCs found: {state.get('iocs', [])}\n"
        f"MITRE techniques: {state.get('mitre_techniques', [])}\n"
    )


def build_recommendation_prompt(state: dict) -> str:
    return (
        f"Alert: {state.get('alert_text', '')}\n\n"
        f"IOCs: {state.get('iocs', [])}\n"
        f"MITRE techniques: {state.get('mitre_techniques', [])}\n"
        f"Risk score: {state.get('risk_score')} ({state.get('severity_prediction')})\n"
        f"Similar past incidents / playbooks: {state.get('rag_matches', [])}\n"
    )
