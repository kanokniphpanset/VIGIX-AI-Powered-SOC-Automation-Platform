"""Approval service.

Request, approve and reject. The approver's role is checked against the policy's approval_role.
"""
from __future__ import annotations


class ApprovalService:
    def request(self, plan_id: str, step_key: str) -> dict: raise NotImplementedError
    def approve(self, approval_id: str, user: str, comment: str = "") -> dict: raise NotImplementedError
    def reject(self, approval_id: str, user: str, reason: str) -> dict: raise NotImplementedError
