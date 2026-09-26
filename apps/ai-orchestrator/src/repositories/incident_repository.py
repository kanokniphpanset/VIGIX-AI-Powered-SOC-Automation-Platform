"""Incident repository. PostgreSQL access only; no business decisions."""
from __future__ import annotations


class IncidentRepository:
    def get(self, incident_id: str) -> dict: raise NotImplementedError
