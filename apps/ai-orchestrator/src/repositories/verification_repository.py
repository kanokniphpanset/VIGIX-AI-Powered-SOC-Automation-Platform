"""Verification repository. PostgreSQL access only; no business decisions."""
from __future__ import annotations


class VerificationRepository:
    def save(self, result: dict) -> str: raise NotImplementedError
    def latest_for_plan(self, plan_id: str) -> dict: raise NotImplementedError
