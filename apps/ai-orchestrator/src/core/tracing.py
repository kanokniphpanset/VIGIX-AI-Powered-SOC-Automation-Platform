"""Run tracing. Each graph run gets an id so model / prompt versions can be tied to a plan."""
from __future__ import annotations

import uuid


def new_run_id() -> str:
    return uuid.uuid4().hex
