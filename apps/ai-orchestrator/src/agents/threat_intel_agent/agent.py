from src.graph.state import AgentState
from src.tools.ioc_extraction_tool import extract_iocs
from src.config.settings import settings
from .clients.misp_client import MispClient
from .clients.vt_client import VirusTotalClient
from .clients.otx_client import OtxClient

misp = MispClient(settings.misp_url, settings.misp_api_key)
virustotal = VirusTotalClient(settings.virustotal_api_key)
otx = OtxClient(settings.otx_api_key)


async def run(state: AgentState) -> AgentState:
    """
    ThreatIntelAgent — extracts IOCs from the raw alert and enriches each one
    against MISP / VirusTotal / AlienVault OTX. Any source without a configured
    API key is skipped (not failed) — the agent still returns whatever IOCs it
    found, just without external reputation data attached.
    """
    text = state.get("alert_text", "")
    extracted = extract_iocs(text)

    enriched = []
    for ioc in extracted[:10]:  # cap to avoid hammering rate-limited free-tier APIs
        reputation_score = None
        raw_response: dict = {}

        if ioc["ioc_type"] == "ip":
            vt_result = await virustotal.lookup_ip(ioc["ioc_value"])
            otx_result = await otx.lookup_ip(ioc["ioc_value"])
        elif ioc["ioc_type"] == "domain":
            vt_result = await virustotal.lookup_domain(ioc["ioc_value"])
            otx_result = await otx.lookup_domain(ioc["ioc_value"])
        elif ioc["ioc_type"] == "hash":
            vt_result = await virustotal.lookup_hash(ioc["ioc_value"])
            otx_result = None
        else:
            vt_result = None
            otx_result = None

        misp_result = await misp.lookup(ioc["ioc_value"])

        if vt_result:
            raw_response["virustotal"] = vt_result
            malicious = vt_result.get("malicious", 0)
            total = sum(
                vt_result.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")
            )
            reputation_score = round((malicious / total) * 100, 1) if total else None
        if otx_result:
            raw_response["otx"] = otx_result
        if misp_result:
            raw_response["misp"] = misp_result

        enriched.append(
            {
                "ioc_type": ioc["ioc_type"],
                "ioc_value": ioc["ioc_value"],
                "source": "aggregated",
                "reputation_score": reputation_score,
                "raw_response": raw_response,
            }
        )

    return {"iocs": enriched, "trace": [f"ThreatIntelAgent: found {len(enriched)} IOC(s)"]}
