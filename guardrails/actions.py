"""
guardrails/actions.py — Catalog of response actions analysts may propose.

Every action in this release is SIMULATED: executing an approved action
records the outcome in the audit log and on the incident, and contacts no
external system. No host is isolated, no account disabled, nothing blocked.
Arbitrary action names are rejected; the catalog is the allow-list.
"""

from __future__ import annotations

from dataclasses import dataclass

from guardrails.models import ActionCategory


@dataclass(frozen=True)
class ResponseActionSpec:
    action_name: str
    label: str
    category: ActionCategory
    target_kind: str  # host | ip | user | incident
    description: str


RESPONSE_ACTIONS: dict[str, ResponseActionSpec] = {
    spec.action_name: spec
    for spec in (
        ResponseActionSpec(
            "create_investigation_task",
            "Create investigation task",
            ActionCategory.ADMINISTRATIVE,
            "incident",
            "Open a follow-up task for the SOC queue (simulated ticket).",
        ),
        ResponseActionSpec(
            "isolate_host",
            "Isolate host (simulated)",
            ActionCategory.CONTAINMENT,
            "host",
            "Request network isolation of an endpoint. Simulated: no EDR call is made.",
        ),
        ResponseActionSpec(
            "block_ip",
            "Block IP at perimeter (simulated)",
            ActionCategory.CONTAINMENT,
            "ip",
            "Request a firewall block for an external IP. Simulated: no firewall change.",
        ),
        ResponseActionSpec(
            "disable_account",
            "Disable account (simulated)",
            ActionCategory.REMEDIATION,
            "user",
            "Request an identity-provider account disable. Simulated: no IdP call.",
        ),
        ResponseActionSpec(
            "reset_credentials",
            "Force credential reset (simulated)",
            ActionCategory.REMEDIATION,
            "user",
            "Request a forced password reset. Simulated: no IdP call.",
        ),
    )
}

SIMULATION_NOTICE = "SIMULATED — no external system was contacted; no real-world change was made."
