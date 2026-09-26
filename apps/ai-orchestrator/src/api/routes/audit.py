"""Routes:

GET  /incidents/{id}/audit-log

Every endpoint that changes data checks the caller's role and records who / when.
"""
from __future__ import annotations
