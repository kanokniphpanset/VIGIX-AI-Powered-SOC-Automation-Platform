"""Audit service.

Append-only record of who did what and when: decisions, approvals, executions, plan creation, model and prompt versions.
"""
from __future__ import annotations


class AuditService:
    def record(self, incident_id: str, actor: str, action: str, detail: dict) -> None: raise NotImplementedError
