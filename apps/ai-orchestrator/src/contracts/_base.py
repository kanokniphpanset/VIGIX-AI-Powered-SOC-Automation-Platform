"""Shared Pydantic base for this package's contracts — same convention as decision_agent/models.py::_CamelModel (camelCase JSON, snake_case Python), redeclared here rather than imported since decision_agent is out of scope to depend on for this task."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, frozen=True, extra="ignore")
