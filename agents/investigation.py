"""
agents/investigation.py — Investigation context retrieval and evidence aggregation.

Aggregates structured evidence from OCSF findings, Phase 4 resolution results,
and Phase 5 Neo4j graph context. Strictly distinguishes observed empirical facts
from analytical inferences and reports database unavailability without fabrication.
"""

from __future__ import annotations

import time

from agents.models import (
    EvidenceFact,
    EvidenceInference,
    InvestigationContext,
)
from core.logger import get_logger
from graph.client import GraphError, Neo4jClient
from graph.models import ResolutionResult
from normalization.models import OCSFSecurityFinding

logger = get_logger("agents.investigation")


class InvestigationService:
    """Retrieves and synthesizes investigation context from telemetry and graph memory.

    Features:
    - Queries the Neo4j knowledge graph using bounded parameters and timeouts.
    - Accurately separates empirical facts (observed in telemetry or graph) from inferences.
    - Gracefully handles offline or failing graph databases with partial context.
    - Never fabricates missing evidence or graph relationships.
    """

    def __init__(self, graph_client: Neo4jClient | None = None) -> None:
        self._graph_client = graph_client

    async def build_context(
        self,
        finding: OCSFSecurityFinding,
        resolution: ResolutionResult | None = None,
        max_depth: int = 1,
    ) -> InvestigationContext:
        """Construct structured investigation context for a security finding.

        Args:
            finding: The normalized OCSF security finding under investigation.
            resolution: Optional Phase 4 resolution result for the finding.
            max_depth: Maximum neighborhood traversal depth in the knowledge graph (1-2).

        Returns:
            InvestigationContext: Separated facts, inferences, graph entities, and missing data indicators.
        """
        finding_id = finding.finding_info.uid
        context = InvestigationContext(finding_id=finding_id, retrieved_at=time.time())

        # 1. Extract directly observed empirical facts from the normalized finding
        self._extract_finding_facts(finding, context)

        # 2. Extract facts and inferences from entity resolution
        if resolution is not None:
            self._extract_resolution_evidence(finding, resolution, context)

        # 3. Query Neo4j Knowledge Graph if client is available
        if self._graph_client is not None:
            await self._query_graph_context(finding, context, max_depth)
        else:
            context.graph_available = False
            context.missing_evidence.append("Neo4j client not configured; historical context unavailable")

        return context

    # ── Internal Extraction Helpers ──────────────────────────────────────────

    def _extract_finding_facts(
        self,
        finding: OCSFSecurityFinding,
        context: InvestigationContext,
    ) -> None:
        """Extract baseline empirical facts directly present in the OCSF alert."""
        # Fact 1: Alert occurrence and classification
        context.observed_facts.append(
            EvidenceFact(
                fact_type="telemetry",
                source="wazuh_alert",
                description=(
                    f"Security finding '{finding.finding_info.title}' reported with "
                    f"severity {finding.severity} (level {finding.severity_id})"
                ),
                timestamp=finding.metadata.original_time,
                properties={
                    "severity": finding.severity,
                    "severity_id": finding.severity_id,
                    "types": finding.finding_info.types,
                    "raw_id": finding.finding_info.uid,
                },
            )
        )

        # Fact 2: Host / Asset device
        if finding.device is not None:
            context.observed_facts.append(
                EvidenceFact(
                    fact_type="device",
                    source="wazuh_agent",
                    description=(
                        f"Associated with host '{finding.device.name or 'Unknown'}' "
                        f"(agent_id: {finding.device.uid or 'None'})"
                    ),
                    properties={
                        "name": finding.device.name,
                        "uid": finding.device.uid,
                        "ip": finding.device.ip,
                    },
                )
            )
        else:
            context.missing_evidence.append("Device/Host attribute missing in alert telemetry")

        # Fact 3: User identity
        if finding.user is not None and finding.user.name:
            context.observed_facts.append(
                EvidenceFact(
                    fact_type="user",
                    source="wazuh_log",
                    description=f"Involves user account '{finding.user.name}'",
                    properties={"username": finding.user.name},
                )
            )
            # Analytical inference on privileged accounts
            if finding.user.name.lower() in ("root", "admin", "administrator", "system", "sudo"):
                context.inferences.append(
                    EvidenceInference(
                        inference_type="privileged_account_targeted",
                        rationale=f"User '{finding.user.name}' is an administrative/privileged account",
                        confidence=0.95,
                        derived_from=["user_account"],
                    )
                )

        # Fact 4: Network endpoints
        src_ip = finding.src_endpoint.ip if finding.src_endpoint else None
        dst_ip = finding.dst_endpoint.ip if finding.dst_endpoint else None
        if src_ip or dst_ip:
            context.observed_facts.append(
                EvidenceFact(
                    fact_type="network",
                    source="wazuh_network",
                    description=f"Network activity observed: {src_ip or 'unknown'} -> {dst_ip or 'unknown'}",
                    properties={
                        "src_ip": src_ip,
                        "src_port": finding.src_endpoint.port if finding.src_endpoint else None,
                        "dst_ip": dst_ip,
                        "dst_port": finding.dst_endpoint.port if finding.dst_endpoint else None,
                        "protocol": finding.src_endpoint.protocol_name if finding.src_endpoint else None,
                    },
                )
            )

        # Fact 5: MITRE ATT&CK techniques
        for attack in finding.attacks:
            if attack.technique and attack.technique.uid:
                t_name = f" ({attack.technique.name})" if attack.technique.name else ""
                tactic_str = f" under {attack.tactic.name}" if attack.tactic and attack.tactic.name else ""
                context.observed_facts.append(
                    EvidenceFact(
                        fact_type="mitre_technique",
                        source="wazuh_rule_mapping",
                        description=f"Mapped to MITRE ATT&CK technique {attack.technique.uid}{t_name}{tactic_str}",
                        properties={
                            "technique_id": attack.technique.uid,
                            "technique_name": attack.technique.name,
                            "tactic": attack.tactic.name if attack.tactic else None,
                        },
                    )
                )

    def _extract_resolution_evidence(
        self,
        finding: OCSFSecurityFinding,
        resolution: ResolutionResult,
        context: InvestigationContext,
    ) -> None:
        """Incorporate Phase 4 entity-resolution results and identify conflicts."""
        # Report conflicts as explicit conflicting evidence
        for conflict in resolution.conflicts:
            context.conflicting_evidence.append(conflict.reason)
            context.inferences.append(
                EvidenceInference(
                    inference_type="identity_ambiguity",
                    rationale=f"Entity resolution conflict: {conflict.reason}",
                    confidence=0.5,
                    derived_from=[conflict.existing_entity_id],
                )
            )

        # Report unresolved items as missing evidence
        for unres in resolution.unresolved:
            context.missing_evidence.append(
                f"Unresolved {unres.get('entity_type', 'Entity')}: {unres.get('reason', 'Missing evidence')}"
            )

    async def _query_graph_context(
        self,
        finding: OCSFSecurityFinding,
        context: InvestigationContext,
        max_depth: int,
    ) -> None:
        """Query Neo4j knowledge graph for historical findings and connected neighbors."""
        assert self._graph_client is not None
        finding_id = finding.finding_info.uid

        try:
            # 1. Query incident neighborhood in graph
            bounded_depth = max(1, min(max_depth, 2))
            neighborhood = await self._graph_client.get_entity_neighborhood(
                f"finding:{finding_id}",
                depth=bounded_depth,
            )

            if neighborhood.get("center") is not None:
                context.entities_found = neighborhood.get("neighbors", [])
                context.relationships_found = neighborhood.get("relationships", [])
                context.observed_facts.append(
                    EvidenceFact(
                        fact_type="graph_neighborhood",
                        source="neo4j_graph",
                        description=(
                            f"Graph neighborhood retrieved: {len(context.entities_found)} entities, "
                            f"{len(context.relationships_found)} relationships"
                        ),
                        properties={"depth": bounded_depth},
                    )
                )

            # 2. Check for historical alert repetition on the same asset (if asset is known)
            if finding.device and finding.device.uid and finding.device.uid != "000":
                agent_id = finding.device.uid.strip()
                canonical_asset_id = f"asset:agent:{agent_id}"

                cypher = """
                MATCH (a:Asset {id: $asset_id})<-[:AFFECTS]-(inc:Incident)
                WHERE inc.id <> $current_id
                RETURN count(DISTINCT inc) AS hist_count,
                       collect(DISTINCT inc.id)[..5] AS recent_finding_ids
                """
                records = await self._graph_client.run_query(
                    cypher,
                    {"asset_id": canonical_asset_id, "current_id": f"finding:{finding_id}"},
                )

                if records:
                    hist_count = int(records[0].get("hist_count", 0))
                    context.historical_finding_count = hist_count

                    if hist_count > 0:
                        context.observed_facts.append(
                            EvidenceFact(
                                fact_type="historical_repetition",
                                source="neo4j_graph",
                                description=(
                                    f"Asset '{finding.device.name or agent_id}' was targeted in "
                                    f"{hist_count} previous security incident(s)"
                                ),
                                properties={
                                    "historical_count": hist_count,
                                    "recent_findings": records[0].get("recent_finding_ids", []),
                                },
                            )
                        )
                        if hist_count >= 3:
                            context.inferences.append(
                                EvidenceInference(
                                    inference_type="repeated_target_asset",
                                    rationale=(
                                        f"High recurrence: asset has {hist_count} prior security alerts "
                                        "in the knowledge graph"
                                    ),
                                    confidence=0.9,
                                    derived_from=[canonical_asset_id],
                                )
                            )

        except GraphError as err:
            context.graph_available = False
            context.lookup_error = str(err)
            context.missing_evidence.append(f"Graph lookup failed ({err}); historical context incomplete")
            logger.warning("investigation_graph_lookup_failed", finding_id=finding_id, error=str(err))
        except Exception as err:
            context.graph_available = False
            context.lookup_error = str(err)
            context.missing_evidence.append(f"Unexpected graph failure ({err}); historical context incomplete")
            logger.warning("investigation_graph_unexpected_error", finding_id=finding_id, error=str(err))
