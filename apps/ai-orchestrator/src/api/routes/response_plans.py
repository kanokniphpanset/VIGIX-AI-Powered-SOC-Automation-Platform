"""Routes:

GET  /incidents/{id}/response-plans        plan history
GET  /response-plans/{plan_id}             resolved plan: summary, why, runbook snapshot, steps (names + versions, not just ids)
POST /incidents/{id}/next-plan             create the next plan (cycle + 1)

Every endpoint that changes data checks the caller's role and records who / when.
"""
from __future__ import annotations
