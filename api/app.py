"""
api/app.py — FastAPI application factory for ThreatFusion AI.

Startup (lifespan) wires one shared object graph:
  settings → repository (postgres/sqlite/memory) → restore persisted state
  → GuardrailEngine (approval + audit hooks write through to the repository)
  → Neo4j client (only if reachable; otherwise the reason is reported)
  → EnrichmentService (MISP if configured + synthetic demo feed in demo mode)
  → AlertWorkflowRunner → SOCService → routes
  → optional Wazuh poller feeding the same ingest path.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agents.narrative import NarrativeGenerator
from api.auth import APIKeyRegistry, configure_registry
from api.persistence import build_repository
from api.ratelimit import (
    AuthFailureGuard,
    BodySizeLimitMiddleware,
    BodyTooLargeError,
    RateLimitMiddleware,
    SlidingWindowLimiter,
)
from api.routes import init_api_dependencies, router
from api.store import InvestigationStore
from core.config import AppSettings, get_settings
from core.logger import get_logger
from graph.client import Neo4jClient
from guardrails.approval import ApprovalRequest, ApprovalService
from guardrails.audit import AuditEvent, HashChainAuditStore
from guardrails.engine import GuardrailEngine, GuardrailPolicy
from ingestion.cmdb import MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.intel import DemoIntelFeed
from ingestion.misp import MISPClient
from orchestrator.workflow import AlertWorkflowRunner

logger = get_logger("api.app")


async def _connect_neo4j(settings: AppSettings, runtime: dict[str, Any]) -> Neo4jClient | None:
    if not settings.neo4j_enabled:
        runtime["neo4j_reason"] = "Disabled (NEO4J_ENABLED=false)"
        return None
    client: Neo4jClient | None = None
    try:
        client = Neo4jClient(settings=settings, timeout=5.0)
        await client.verify_connectivity()
        await client.init_schema()
        runtime["neo4j_reason"] = "connected"
        return client
    except Exception as err:
        runtime["neo4j_reason"] = f"Unavailable at startup ({type(err).__name__}); graph falls back to per-alert resolution"
        logger.warning("neo4j_unavailable", error=str(err))
        if client is not None:
            await client.aclose()
        return None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Build dependencies from settings; fail closed if persistence is unavailable."""
    settings = get_settings()
    runtime: dict[str, Any] = {"demo_mode": settings.demo_mode}
    logger.info("startup_config", **settings.safe_summary())

    registry = APIKeyRegistry(settings.api_keys)
    configure_registry(registry)
    if not registry.configured:
        logger.warning("no_api_keys_configured", detail="All protected endpoints will return 401")

    repository = build_repository(settings.persistence_backend, settings.postgres_dsn, settings.sqlite_path)
    await repository.start()  # raises → app refuses to start (fail closed)
    persisted = await repository.load_all()

    store = InvestigationStore(max_capacity=5000, repository=repository)
    store.restore(persisted)

    approvals = ApprovalService(default_timeout_seconds=float(settings.approval_timeout_seconds))
    approvals.restore([ApprovalRequest.model_validate(a) for a in persisted["approvals"]])
    audit = HashChainAuditStore()
    ok, err = audit.restore([AuditEvent.model_validate(e) for e in persisted["audit"]])
    if not ok:
        logger.error("audit_chain_verification_failed_on_startup", error=err)
    approvals.on_change = store.queue_approval
    audit.on_append = store.queue_audit

    engine = GuardrailEngine(
        policy=GuardrailPolicy(
            max_blast_radius=settings.max_isolation_blast_radius,
            privileged_accounts_require_approval=settings.privileged_accounts_require_manual_override,
        ),
        approval_service=approvals,
        audit_store=audit,
    )

    graph_client = await _connect_neo4j(settings, runtime)
    misp = MISPClient(settings=settings)
    enrichment = EnrichmentService(
        misp_client=misp,
        cmdb_provider=MockIAMCMDBProvider(),
        demo_feed=DemoIntelFeed() if settings.demo_mode else None,
    )
    runner = AlertWorkflowRunner(
        settings=settings,
        graph_client=graph_client,
        guardrail_engine=engine,
        enable_graph_persistence=graph_client is not None,
        enrichment_service=enrichment,
    )
    narrative = NarrativeGenerator(
        provider=settings.llm_provider,
        model=settings.reasoning_llm_model,
        api_key=settings.llm_api_key,
        base_url=settings.llm_base_url,
        timeout_seconds=settings.llm_timeout_seconds,
    )
    service = init_api_dependencies(
        runner=runner,
        misp_client=misp,
        enrichment_service=enrichment,
        guardrail_engine=engine,
        store=store,
        narrative=narrative,
        runtime=runtime,
    )
    audit.log_event(
        actor="system", operation="api_startup", decision="RECORD", policy_id=engine.policy.policy_id,
        outcome=f"API started (persistence={repository.backend}, neo4j={runtime['neo4j_reason']})",
    )
    await store.flush()

    poller = None
    if settings.wazuh_enabled:
        from ingestion.poller import WazuhAlertPoller
        from ingestion.wazuh_client import WazuhClient

        wazuh_client = WazuhClient(settings=settings)

        async def handle(alerts: list[dict[str, Any]]) -> None:
            for raw in alerts:
                await service.ingest(raw, "wazuh", {"poller": True}, actor="wazuh_poller")

        poller = WazuhAlertPoller(wazuh_client, settings, handler=handle)
        await poller.start()
        runtime["wazuh_status"] = "polling"
        runtime["wazuh_endpoint"] = settings.wazuh_alerts_endpoint

    logger.info("api_ready", persistence=repository.backend, neo4j=runtime["neo4j_reason"])
    try:
        yield
    finally:
        if poller is not None:
            await poller.stop()
        if graph_client is not None:
            await graph_client.aclose()
        await repository.close()
        logger.info("api_shutdown")


def create_app(settings: AppSettings | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    cfg = settings
    if cfg is None:
        try:
            cfg = get_settings()
        except Exception:  # tests may build the app without a full environment
            cfg = None
    origins = cfg.cors_origin_list if cfg else ["http://localhost:5173", "http://127.0.0.1:5173"]
    max_body = cfg.max_request_bytes if cfg else 262_144
    per_minute = cfg.rate_limit_per_minute if cfg else 600
    auth_failures = cfg.auth_max_failures if cfg else 10
    lockout = cfg.auth_lockout_seconds if cfg else 300

    app = FastAPI(
        title="ThreatFusion AI Investigation API",
        description=(
            "Agentic SOC copilot: alert ingestion, OCSF normalization, deterministic triage, "
            "incident correlation, temporal knowledge graph, human-approved (simulated) response, "
            "and a hash-chained audit log. Authenticate with `Authorization: Bearer <api key>`."
        ),
        version="1.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    )

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cache-Control"] = "no-store"
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, BodyTooLargeError):
            return JSONResponse({"detail": f"Request body exceeds {max_body} bytes"}, status_code=413)
        logger.error("unhandled_exception", path=request.url.path, error=type(exc).__name__)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    # Outermost layers (added last): throttle first, then cap body size.
    app.state.auth_guard = AuthFailureGuard(auth_failures, float(lockout))
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_body)
    app.add_middleware(RateLimitMiddleware, limiter=SlidingWindowLimiter(per_minute, 60.0))

    app.include_router(router)
    return app


# Root app instance for uvicorn
app = create_app()
