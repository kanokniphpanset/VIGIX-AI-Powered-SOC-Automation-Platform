import asyncio
import sys
from contextlib import asynccontextmanager

# psycopg's async connection pool (used by the Phase 4 Postgres checkpointer)
# cannot run under asyncio's default ProactorEventLoop on Windows — every
# connection attempt fails with "Psycopg cannot use the 'ProactorEventLoop'
# to run in async mode." Must be set before uvicorn's asyncio.run() creates
# the server's event loop, i.e. at import time here, not inside lifespan().
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from fastapi import FastAPI
from src.api.routes.run_pipeline import router as pipeline_router
from src.api.routes.ingest_alert import router as ingest_alert_router
from src.api.routes.embeddings import router as embeddings_router
from src.api.routes.kpi import router as kpi_router
from src.api.routes.recommendations import router as recommendations_router
from src.graph.checkpointer import init_checkpointer, close_checkpointer


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Phase 4 — PostgreSQL-backed LangGraph checkpointing (spec section 9).
    # Runs the checkpointer's own migration (idempotent) before the app
    # starts serving /pipeline/run requests.
    await init_checkpointer()
    yield
    await close_checkpointer()


app = FastAPI(title="AI-Driven SOAR Automation Platform - AI Orchestrator", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "service": "soar-ai-orchestrator"}


app.include_router(pipeline_router, prefix="/pipeline", tags=["pipeline"])
app.include_router(ingest_alert_router, prefix="/pipeline", tags=["pipeline"])
app.include_router(embeddings_router, prefix="/embeddings", tags=["embeddings"])
app.include_router(kpi_router, prefix="/kpi", tags=["kpi"])
app.include_router(recommendations_router, prefix="/recommendations", tags=["recommendations"])
