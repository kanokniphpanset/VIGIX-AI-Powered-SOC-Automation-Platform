"""Prompt loader. Prompts live in text files, named <name>/<version>.txt, so a plan can record which one made it."""
from __future__ import annotations

from pathlib import Path

_BASE = Path(__file__).parent


class PromptNotFound(FileNotFoundError):
    pass


def load_prompt(name: str, version: str) -> str:
    path = _BASE / name / f"{version}.txt"
    if not path.is_file():
        raise PromptNotFound(f"prompt {name}/{version} not found at {path}")
    return path.read_text(encoding="utf-8")
