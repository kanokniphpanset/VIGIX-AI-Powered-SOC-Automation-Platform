"""Routes:

POST /approvals/{id}/approve
POST /approvals/{id}/reject      reason required

Every endpoint that changes data checks the caller's role and records who / when.
"""
from __future__ import annotations
