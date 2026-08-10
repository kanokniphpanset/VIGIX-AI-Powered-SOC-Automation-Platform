from fastapi import FastAPI
from src.api.routes.run_pipeline import router as pipeline_router

app = FastAPI(title="AI-Driven SOAR Automation Platform - AI Orchestrator")


@app.get("/health")
def health():
    return {"status": "ok", "service": "soar-ai-orchestrator"}


app.include_router(pipeline_router, prefix="/pipeline", tags=["pipeline"])
