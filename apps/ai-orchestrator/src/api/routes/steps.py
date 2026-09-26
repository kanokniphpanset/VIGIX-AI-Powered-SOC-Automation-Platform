"""Routes:

POST /response-plans/{plan_id}/steps/{key}/start
POST /response-plans/{plan_id}/steps/{key}/tasks/{task_id}
POST /response-plans/{plan_id}/steps/{key}/complete   actual_result is required and comes from a person
POST /response-plans/{plan_id}/steps/{key}/skip
POST /response-plans/{plan_id}/steps/{key}/decision   decision, reason; decided_by / decided_at are set by the server

Every endpoint that changes data checks the caller's role and records who / when.
"""
from __future__ import annotations
