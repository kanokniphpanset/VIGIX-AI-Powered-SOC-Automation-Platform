"""
asset_criticality_loader.py — restores a missing, previously-documented
module (see prompt_loader.py's own docstring for the full context of why
`apps/ai-orchestrator/resources/` had to be recreated). Reconstructed
against resources/assets/asset-criticality-catalog.yaml's own extensive
header comments and resources/README.md, which fully specify this
loader's behavior. Only the ONE method src/ingestion/agent_state_builder.py
actually calls (`resolve_with_metadata`) is implemented — this is not a
general-purpose YAML config framework, just what the real caller needs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CATALOG_PATH = _REPO_ROOT / "resources" / "assets" / "asset-criticality-catalog.yaml"


class ResourceAssetCriticalityProvider:
    def __init__(self, catalog_path: Path | None = None):
        self._catalog_path = catalog_path or _CATALOG_PATH
        self._default_tier = "tier2_high"
        self._by_hostname: dict[str, str] = {}
        self._by_ip: dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        self._by_hostname = {}
        self._by_ip = {}
        if not self._catalog_path.exists():
            return
        data = yaml.safe_load(self._catalog_path.read_text(encoding="utf-8")) or {}
        self._default_tier = data.get("default_tier", "tier2_high")
        for entry in data.get("assets") or []:
            tier = entry.get("tier")
            if not tier:
                continue
            hostname = entry.get("hostname")
            ip = entry.get("ip")
            if hostname:
                self._by_hostname[hostname.strip().lower()] = tier
            if ip:
                self._by_ip[ip.strip()] = tier

    def resolve_with_metadata(self, hostname: str | None, ip: str | None) -> tuple[str, bool]:
        """Hostname match takes precedence over IP (IPs can be reassigned by
        DHCP; a catalogued hostname is the more stable identifier). Falls
        back to default_tier with is_known=False — never fabricates a tier
        for an uncatalogued asset."""
        if hostname and hostname.strip().lower() in self._by_hostname:
            return self._by_hostname[hostname.strip().lower()], True
        if ip and ip.strip() in self._by_ip:
            return self._by_ip[ip.strip()], True
        return self._default_tier, False
