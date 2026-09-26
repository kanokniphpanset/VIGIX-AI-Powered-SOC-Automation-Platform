"""
embeddings_only_server.py — TEMPORARY test/integration harness, NOT the
application's real entry point (that remains src/main.py). Mounts only:
  - /embeddings  (src/api/routes/embeddings.py — existing, unchanged)
  - /recommendations/generate (src/api/routes/recommendations.py — new
    this task, RAG-retrieval + deterministic candidate-shaping only, no
    LLM call — see that file's own docstring)

Why this exists rather than running the real src.main:app: that module
eagerly imports every agent, including the OLD, separate
decision_agent/recommendation_agent pipeline (via build_graph.py), which
depends on resources/mapping_loader.py — a missing module this task
deliberately does NOT restore, since it exists only to serve that old
pipeline and this task's own instructions say not to build/touch a
recommendation engine beyond the one new endpoint above. (Three OTHER
missing loader modules — prompt_loader.py, asset_criticality_loader.py,
policy_loader.py — WERE restored, because rag_agent/decision_agent
genuinely needed them to import at all; see those files' own docstrings.)

This harness does not duplicate, replace, or bypass RecommendationValidator
— the Node backend still independently re-validates everything this
endpoint proposes before persisting anything.

Run with: .venv\\Scripts\\python.exe scripts\\embeddings_only_server.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # apps/ai-orchestrator

from fastapi import FastAPI
import uvicorn

from src.api.routes.embeddings import router as embeddings_router
from src.api.routes.recommendations import router as recommendations_router

app = FastAPI(title="RAG + embeddings test harness (not the real app entry point)")
app.include_router(embeddings_router, prefix="/embeddings", tags=["embeddings"])
app.include_router(recommendations_router, prefix="/recommendations", tags=["recommendations"])


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
