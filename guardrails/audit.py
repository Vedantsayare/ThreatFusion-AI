"""
guardrails/audit.py — Tamper-evident, hash-chained audit logging for security decisions.

Provides:
- AuditEvent: Typed, sanitized audit record.
- HashChainAuditStore: Append-only storage with cryptographic SHA-256 hash chaining.
- Cryptographic chain verification: Detects any modification, insertion, or deletion.
- Log sanitization: Strips CRLF/control characters and redacts secrets (passwords, tokens).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Patterns for redacting sensitive secrets
SECRET_PATTERNS = [
    re.compile(r"(password|passwd|pwd|secret|api_key|token|auth_token)\s*[:=]\s*['\"]?([^'\"\s,;]+)", re.IGNORECASE),
    re.compile(r"(Bearer\s+)([a-zA-Z0-9\._\-]+)", re.IGNORECASE),
]

# Control characters to strip to prevent log/CRLF injection
CONTROL_CHAR_PATTERN = re.compile(r"[\r\n\x00-\x1f\x7f-\x9f]")


def sanitize_audit_text(text: str) -> str:
    """Sanitize text to prevent log injection (CRLF) and redact sensitive credentials."""
    if not text:
        return ""

    # Redact credentials
    sanitized = text
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub(r"\1=***REDACTED***", sanitized)

    # Replace newlines and carriage returns with visual escapes
    sanitized = sanitized.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")

    # Remove remaining non-printable control characters
    sanitized = CONTROL_CHAR_PATTERN.sub("", sanitized)
    return sanitized


class AuditEvent(BaseModel):
    """Immutable audit record representing a security-relevant decision or state change."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: f"aud-{uuid.uuid4().hex[:12]}")
    timestamp: float = Field(default_factory=time.time)
    iso_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    actor: str
    operation: str
    decision: str  # e.g. "ALLOW", "REQUIRE_APPROVAL", "DENY", "ERROR"
    policy_id: str
    evidence_refs: list[str] = Field(default_factory=list)
    approval_id: str | None = None
    outcome: str
    error_category: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Hash chaining fields for tamper evidence
    prev_event_hash: str = "0" * 64
    event_hash: str = ""

    def compute_hash(self, prev_hash: str) -> str:
        """Compute deterministic SHA-256 hash linking this event to the previous event."""
        canonical = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "operation": self.operation,
            "decision": self.decision,
            "policy_id": self.policy_id,
            "evidence_refs": sorted(self.evidence_refs),
            "approval_id": self.approval_id,
            "outcome": self.outcome,
            "error_category": self.error_category,
            "metadata": self.metadata,
            "prev_event_hash": prev_hash,
        }
        serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class HashChainAuditStore:
    """Append-only audit store with cryptographic SHA-256 hash chaining.

    Every logged event links to the hash of the preceding event.
    Calling verify_chain_integrity() validates that the chain is unbroken and unmodified.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: str | None = None) -> None:
        self.log_path = log_path
        self._events: list[AuditEvent] = []
        self._last_hash: str = self.GENESIS_HASH

    @property
    def event_count(self) -> int:
        """Total number of audit events recorded."""
        return len(self._events)

    def log_event(
        self,
        actor: str,
        operation: str,
        decision: str,
        policy_id: str,
        outcome: str,
        evidence_refs: list[str] | None = None,
        approval_id: str | None = None,
        error_category: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Sanitize fields, compute chained SHA-256 hash, and append event to store."""
        # Sanitize all untrusted text inputs
        clean_actor = sanitize_audit_text(actor)
        clean_operation = sanitize_audit_text(operation)
        clean_outcome = sanitize_audit_text(outcome)
        clean_evidence = [sanitize_audit_text(ref) for ref in (evidence_refs or [])]

        clean_meta: dict[str, Any] = {}
        if metadata:
            for k, v in metadata.items():
                if isinstance(v, str):
                    clean_meta[k] = sanitize_audit_text(v)
                else:
                    clean_meta[k] = v

        event = AuditEvent(
            actor=clean_actor,
            operation=clean_operation,
            decision=decision,
            policy_id=policy_id,
            evidence_refs=clean_evidence,
            approval_id=approval_id,
            outcome=clean_outcome,
            error_category=error_category,
            metadata=clean_meta,
            prev_event_hash=self._last_hash,
        )

        event.event_hash = event.compute_hash(self._last_hash)
        self._events.append(event)
        self._last_hash = event.event_hash

        # Optional append-only file persistence
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")

        return event

    def get_events(self) -> list[AuditEvent]:
        """Return a copy of the recorded audit events."""
        return list(self._events)

    def verify_chain_integrity(self) -> tuple[bool, str | None]:
        """Verify the cryptographic hash chain across all stored events.

        Returns:
            tuple[bool, str | None]: (True, None) if unbroken, or (False, error_reason).
        """
        if not self._events:
            return True, None

        expected_prev_hash = self.GENESIS_HASH

        for idx, event in enumerate(self._events):
            # 1. Verify link to previous event
            if event.prev_event_hash != expected_prev_hash:
                return (
                    False,
                    f"Chain broken at event #{idx} ({event.event_id}): expected prev_hash '{expected_prev_hash}', got '{event.prev_event_hash}'",
                )

            # 2. Recompute and verify event hash
            recomputed = event.compute_hash(expected_prev_hash)
            if event.event_hash != recomputed:
                return (
                    False,
                    f"Tamper detected at event #{idx} ({event.event_id}): stored hash '{event.event_hash}' does not match recomputed '{recomputed}'",
                )

            expected_prev_hash = event.event_hash

        return True, None
