"""
api/app.py — FastAPI application factory for ThreatFusion AI.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import init_api_dependencies, router
from api.store import default_investigation_store
from core.logger import get_logger

logger = get_logger("api.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown tasks."""
    logger.info("Initializing ThreatFusion AI API dependencies...")
    init_api_dependencies(store=default_investigation_store)
    logger.info("API initialized successfully.")
    yield
    logger.info("ThreatFusion AI API shutting down.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="ThreatFusion AI Investigation API",
        description="Unified SOC Investigation, MISP Enrichment, CMDB Context, and Human-in-the-Loop Approvals",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Configure CORS for local development and dashboard access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routes
    app.include_router(router)

    return app


# Root app instance for uvicorn
app = create_app()
