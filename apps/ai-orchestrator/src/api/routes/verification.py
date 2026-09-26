"""Routes:

POST /response-plans/{plan_id}/verification/run
GET  /response-plans/{plan_id}/verification

Every endpoint that changes data checks the caller's role and records who / when.
"""
from __future__ import annotations
