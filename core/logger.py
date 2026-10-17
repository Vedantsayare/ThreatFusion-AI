"""
core/logger.py — Structured JSON logging for ThreatFusion AI.

Uses structlog for consistent, machine-readable output.
Every log event carries a timestamp and log level.
Secrets must never appear as log values — use core.config.safe_summary() instead.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from core.config import get_settings


def _get_log_level() -> int:
    """Resolve the numeric log level from the application settings."""
    settings = get_settings()
    return getattr(logging, settings.log_level.upper(), logging.INFO)


def configure_logging() -> None:
    """
    Configure structlog and the stdlib logging root logger.

    Call once at application startup (e.g., in FastAPI lifespan or main.py).
    Subsequent calls are idempotent because structlog wraps the same root logger.
    """
    log_level = _get_log_level()

    # Configure stdlib root logger to capture everything
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Attach a JSON formatter to the root stdlib handler
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(log_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a named structlog logger.

    structlog.get_logger() is typed as Any; the cast satisfies
    mypy strict mode without altering runtime behaviour.
    """
    from typing import cast

    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
