"""Dependency wiring (settings, repositories, services) for the API and graph."""
from __future__ import annotations

from functools import lru_cache

from .config import Settings


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()
