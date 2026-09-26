"""Recommendation (response plan) repository. PostgreSQL access only; no business decisions."""
from __future__ import annotations


class RecommendationRepository:
    def save_plan(self, plan: dict) -> str: raise NotImplementedError
    def get_plan(self, plan_id: str) -> dict: raise NotImplementedError
    def list_plans(self, incident_id: str) -> list[dict]: raise NotImplementedError
