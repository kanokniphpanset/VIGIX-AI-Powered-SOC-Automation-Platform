"""Step execution repository. PostgreSQL access only; no business decisions.

`complete` must stamp completed_at itself (server time) - callers never pass a timestamp in.
"""
from __future__ import annotations

from typing import Optional


class StepExecutionRepository:
    def start(self, plan_id: str, step_key: str, executed_by: str) -> dict: raise NotImplementedError
    def complete(self, plan_id: str, step_key: str, actual_result: str,
                 decision_taken: Optional[str] = None) -> dict: raise NotImplementedError
    def skip(self, plan_id: str, step_key: str, reason: str) -> dict: raise NotImplementedError
    def get(self, plan_id: str, step_key: str) -> dict: raise NotImplementedError
    def list_for_plan(self, plan_id: str) -> list[dict]: raise NotImplementedError
