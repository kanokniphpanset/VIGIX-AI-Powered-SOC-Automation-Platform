"""
prompt_loader.py — restores a missing, previously-documented module.

Confirmed missing (not merely unwired) during a RAG-retrieval integration
task: `apps/ai-orchestrator/resources/` did not exist as a directory at
all, even though `requirements.txt` already declares PyYAML specifically
for "policy YAML and prompt-file frontmatter" and the repo's own
`resources/README.md` + `resources/prompts/README.md` fully document this
loader's contract and every prompt file's exact frontmatter format. This
is a faithful reconstruction against that existing documentation and the
existing `resources/prompts/**/*.md` files it must read — not a new
design.

Contract (resources/README.md, "How loading actually works"): every
resource loader implements `get_all()`, `get_by_id()`, `reload()`.

Frontmatter format (resources/prompts/README.md):
    ---
    id: my-agent.my-prompt
    version: "1"
    variables: [alert_text, risk_score]
    description: One line.
    ---
    Prompt body using {alert_text} and {risk_score} placeholders.

Only `prompt_loader.py` is restored here — `policy_loader.py`,
`mapping_loader.py`, and `asset_criticality_loader.py` are separate,
larger, out-of-scope gaps (see asset_criticality_loader.py, restored
alongside this one only because it sits on the app's startup import path;
the other two are lazy-imported and not required for this task).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROMPTS_DIR = _REPO_ROOT / "resources" / "prompts"


@dataclass(frozen=True)
class Prompt:
    id: str
    version: str
    variables: list[str]
    description: str
    template: str


class PromptLoader:
    def __init__(self, prompts_dir: Path | None = None):
        self._prompts_dir = prompts_dir or _PROMPTS_DIR
        self._by_id: dict[str, Prompt] = {}
        self.reload()

    def reload(self) -> None:
        self._by_id = {}
        if not self._prompts_dir.exists():
            return
        for path in sorted(self._prompts_dir.rglob("*.md")):
            prompt = self._parse(path)
            if prompt is not None:
                self._by_id[prompt.id] = prompt

    def get_all(self) -> list[Prompt]:
        return list(self._by_id.values())

    def get_by_id(self, prompt_id: str) -> Prompt | None:
        return self._by_id.get(prompt_id)

    def render(self, prompt_id: str, **kwargs: object) -> str:
        prompt = self.get_by_id(prompt_id)
        if prompt is None:
            raise KeyError(f"No prompt registered with id '{prompt_id}'")
        missing = [v for v in prompt.variables if v not in kwargs]
        if missing:
            raise ValueError(f"Prompt '{prompt_id}' is missing required variable(s): {missing}")
        return prompt.template.format(**kwargs)

    @staticmethod
    def _parse(path: Path) -> Prompt | None:
        text = path.read_text(encoding="utf-8")
        if not text.startswith("---"):
            return None
        parts = text.split("---", 2)
        if len(parts) < 3:
            return None
        frontmatter = yaml.safe_load(parts[1]) or {}
        body = parts[2].lstrip("\n")

        prompt_id = frontmatter.get("id")
        if not prompt_id:
            return None

        return Prompt(
            id=prompt_id,
            version=str(frontmatter.get("version", "1")),
            variables=list(frontmatter.get("variables") or []),
            description=frontmatter.get("description", ""),
            template=body,
        )
