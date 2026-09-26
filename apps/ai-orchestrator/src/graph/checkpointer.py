"""
Persistent PostgreSQL checkpointing for the LangGraph pipeline (Phase 4,
spec section 9). Uses the same Postgres instance/database everything else
in this service already targets (settings.database_url) — a new schema
of tables (`checkpoints`, `checkpoint_blobs`, `checkpoint_writes`),
managed entirely by langgraph-checkpoint-postgres's own `.setup()`
migration, not Prisma.

`thread_id = execution_id` (spec section 9's own example) — every graph
run is checkpointed under the AgentExecution row the backend already
created, so a checkpoint can be resumed/inspected by the same ID the rest
of the system already uses to refer to this run.

Constructed lazily, not at module import time: AsyncPostgresSaver's own
__init__ calls asyncio.get_running_loop() unconditionally, which raises
outside a running event loop — true at plain `import` time (e.g. pytest
collecting build_graph.py) and would silently make every existing test
that imports build_graph.py require an event loop it doesn't have. Real
construction happens in init_checkpointer(), called from main.py's
FastAPI lifespan, which genuinely does run inside uvicorn's event loop.
"""

from __future__ import annotations

import logging

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from src.config.settings import settings

logger = logging.getLogger("soar.ai-orchestrator.checkpointer")

checkpointer: AsyncPostgresSaver | None = None
_pool: AsyncConnectionPool | None = None


async def init_checkpointer() -> AsyncPostgresSaver:
    """Opens a connection pool, constructs the checkpointer, and runs its
    own migrations. Idempotent — safe to call more than once (e.g. from
    both the FastAPI lifespan and a lazily-triggered first request)."""
    global checkpointer, _pool
    if checkpointer is not None:
        return checkpointer

    _pool = AsyncConnectionPool(
        conninfo=settings.database_url,
        max_size=5,
        open=False,
        kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row},
    )
    await _pool.open()
    checkpointer = AsyncPostgresSaver(_pool)
    await checkpointer.setup()
    logger.info("checkpointer.initialized")
    return checkpointer


async def close_checkpointer() -> None:
    global checkpointer, _pool
    if _pool is not None:
        await _pool.close()
    checkpointer = None
    _pool = None
