#!/var/ossec/framework/python/bin/python3
"""
custom-vigix.py — Wazuh custom integration. Forwards a single Wazuh alert
(as-is, unmodified) to VIGIX's SIEM webhook the instant wazuh-integratord
fires a matching rule. This is the real automatic path — nothing manual,
no analyst has to run a curl command.

Wazuh invokes this script (via the custom-vigix wrapper) once per matching
alert, synchronously, with:
    argv[1] = path to a temp file containing ONE alert as JSON
    argv[2] = API key configured in ossec.conf's <api_key> — reused here as
              the SIEM_WEBHOOK_SECRET shared secret so this script can sign
              requests the same way VigixBackend's webhookAuth.middleware.ts
              verifies them (HMAC-SHA256 over the raw body, sent as
              `X-Webhook-Signature: sha256=<hex>`). Empty/unset means the
              backend has no SIEM_WEBHOOK_SECRET configured either — the
              request is sent unsigned, matching the middleware's own
              "unconfigured secret disables verification" convention.
    argv[3] = hook_url configured in ossec.conf's <hook_url>
    argv[4] = alert options (unused)

Same shape/conventions as Wazuh's own built-in integrations (slack.py,
virustotal.py, pagerduty.py) so this reads familiarly to anyone who has
touched a Wazuh deployment before.

Install: see infra/wazuh-integration/README.md.
"""

import hashlib
import hmac
import json
import logging
import os
import sys

try:
    import requests
except ImportError:
    print("requests module not found — run this with Wazuh's bundled python3 (framework/python/bin/python3), not the system one")
    sys.exit(1)

# Wazuh's own convention: <WAZUH_HOME>/logs/integrations.log, computed
# relative to this file's real location (integrations/), not cwd.
LOG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "logs", "integrations.log")
REQUEST_TIMEOUT_S = 10

# Wazuh's own exit code convention for integration scripts.
ERR_NO_ARG = 1
ERR_FILE_NOT_FOUND = 2
ERR_INVALID_JSON = 3
ERR_HTTP_REQUEST_FAILED = 4

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s custom-vigix: %(levelname)s: %(message)s")
logger = logging.getLogger("custom-vigix")


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        logger.error("missing required arguments — expected: <alert_file> <api_key> <hook_url>")
        return ERR_NO_ARG

    alert_file_path = argv[1]
    webhook_secret = argv[2]
    hook_url = argv[3]

    if not os.path.exists(alert_file_path):
        logger.error("alert file not found: %s", alert_file_path)
        return ERR_FILE_NOT_FOUND

    try:
        with open(alert_file_path, encoding="utf-8") as f:
            alert = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("failed to read/parse alert file %s: %s", alert_file_path, exc)
        return ERR_INVALID_JSON

    external_alert_id = alert.get("id", "unknown")
    rule_id = alert.get("rule", {}).get("id", "unknown")

    # Forwarded as-is — VigixBackend's WazuhAdapter (apps/backend/src/
    # infrastructure/external-services/siem/WazuhAdapter.ts) reads Wazuh's
    # own native alert shape directly (rule.description, rule.level,
    # agent.ip, timestamp, id). No reshaping needed here.
    #
    # Serialized to bytes ourselves (rather than passing json=alert to
    # requests) so the exact bytes we sign are the exact bytes sent as the
    # body — webhookAuth.middleware.ts verifies the signature against
    # req.rawBody, so any mismatch between what's signed and what's sent
    # (e.g. requests' own JSON encoding differing from ours) would make
    # every request fail verification.
    body_bytes = json.dumps(alert).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if webhook_secret:
        signature = hmac.new(webhook_secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        headers["X-Webhook-Signature"] = f"sha256={signature}"

    try:
        response = requests.post(
            hook_url,
            data=body_bytes,
            headers=headers,
            timeout=REQUEST_TIMEOUT_S,
        )
    except requests.exceptions.RequestException as exc:
        logger.error("POST to %s failed for alert id=%s rule=%s: %s", hook_url, external_alert_id, rule_id, exc)
        return ERR_HTTP_REQUEST_FAILED

    if response.status_code == 202:
        body = response.json()
        logger.info(
            "alert id=%s rule=%s forwarded — backend responded %s (executionId=%s)",
            external_alert_id,
            rule_id,
            body.get("status"),
            body.get("executionId"),
        )
        return 0

    # Any non-202 (400/422 validation error, 5xx) — log the body so a
    # malformed-payload issue is diagnosable from integrations.log without
    # needing backend log access. Re-POSTing the *same* alert later is
    # safe either way: the backend's idempotency check (unique on
    # tenantId+externalAlertId) means a retry never creates a duplicate.
    logger.error("alert id=%s rule=%s rejected — HTTP %s: %s", external_alert_id, rule_id, response.status_code, response.text[:500])
    return ERR_HTTP_REQUEST_FAILED


if __name__ == "__main__":
    sys.exit(main(sys.argv))
