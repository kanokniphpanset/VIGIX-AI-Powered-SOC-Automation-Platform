"""Evidence repository. PostgreSQL access only; no business decisions."""
from __future__ import annotations


class EvidenceRepository:
    def list_for_incident(self, incident_id: str) -> list[dict]: raise NotImplementedError
    def add(self, evidence: dict) -> str: raise NotImplementedError
