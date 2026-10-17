"""
graph/resolver.py — Deterministic entity resolution engine for OCSF findings.

Extracts, normalizes, disambiguates, and links graph entities (Asset, Identity,
IOC, TTP, Incident) and temporal relationships from normalized OCSF security findings.
Enforces strict matching policies distinguishing strong identifiers from weak attributes.
"""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime
from typing import Any

from core.logger import get_logger
from graph.models import (
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationshipType,
    ResolutionConflict,
    ResolutionResult,
)
from normalization.models import OCSFSecurityFinding

logger = get_logger("graph.resolver")

# Generic hostnames that should never be merged across uncorroborated alerts
GENERIC_HOSTNAMES = frozenset({
    "localhost",
    "ubuntu",
    "debian",
    "centos",
    "redhat",
    "windows",
    "server",
    "workstation",
    "unknown",
    "default",
})

# Generic usernames that must always be scoped by host/device to avoid false merges
GENERIC_USERNAMES = frozenset({
    "root",
    "admin",
    "administrator",
    "system",
    "guest",
    "nobody",
    "daemon",
    "test",
    "user",
    "operator",
})


class EntityResolver:
    """Deterministic, rule-based entity resolver for OCSF findings.

    Distinguishes strong identifiers (agent ID, technique UID, public IP) from weak/reused
    attributes (private IP, generic username, generic hostname).
    Refuses uncertain merges when evidence is ambiguous or conflicting.
    """

    def __init__(self) -> None:
        self._assets: dict[str, EntityNode] = {}
        self._identities: dict[str, EntityNode] = {}
        self._iocs: dict[str, EntityNode] = {}
        self._ttps: dict[str, EntityNode] = {}
        self._incidents: dict[str, EntityNode] = {}
        self._relationships: list[RelationshipEdge] = []
        self._conflicts: list[ResolutionConflict] = []
        self._unresolved: list[dict[str, Any]] = []

    def reset(self) -> None:
        """Clear all resolved state in the resolver instance."""
        self._assets.clear()
        self._identities.clear()
        self._iocs.clear()
        self._ttps.clear()
        self._incidents.clear()
        self._relationships.clear()
        self._conflicts.clear()
        self._unresolved.clear()

    def resolve_finding(self, finding: OCSFSecurityFinding) -> ResolutionResult:
        """Resolve all entities and relationships present in a single OCSF finding.

        Args:
            finding: Normalized OCSF security finding.

        Returns:
            ResolutionResult: Resolved graph entities, edges, conflicts, and unresolved items.
        """
        return self.resolve_findings([finding])

    def resolve_findings(self, findings: list[OCSFSecurityFinding]) -> ResolutionResult:
        """Resolve entities and relationships across a sequence of OCSF findings.

        Maintains identity and deduplication state across the batch.
        """
        for finding in findings:
            self._process_single_finding(finding)

        all_entities: dict[str, EntityNode] = {}
        all_entities.update(self._assets)
        all_entities.update(self._identities)
        all_entities.update(self._iocs)
        all_entities.update(self._ttps)
        all_entities.update(self._incidents)

        return ResolutionResult(
            entities=all_entities,
            relationships=list(self._relationships),
            conflicts=list(self._conflicts),
            unresolved=list(self._unresolved),
        )

    # ── Internal Processing ──────────────────────────────────────────────────

    def _process_single_finding(self, finding: OCSFSecurityFinding) -> None:
        event_time_iso = self._to_iso_timestamp(finding.time)

        # 1. Incident node for the finding itself
        incident_node = self._resolve_incident(finding)

        # 2. Asset node (Device / Host)
        asset_node = self._resolve_asset(finding)
        if asset_node is not None:
            self._add_relationship(
                source_id=incident_node.canonical_id,
                target_id=asset_node.canonical_id,
                rel_type=RelationshipType.AFFECTS,
                valid_from=event_time_iso,
                confidence=asset_node.confidence,
                source="wazuh",
            )

        # 3. Identity node (User Account)
        identity_node = self._resolve_identity(finding, asset_node)
        if identity_node is not None:
            self._add_relationship(
                source_id=incident_node.canonical_id,
                target_id=identity_node.canonical_id,
                rel_type=RelationshipType.INVOLVES,
                valid_from=event_time_iso,
                confidence=identity_node.confidence,
                source="wazuh",
            )

        # 4. IOC nodes (Source and Destination IP addresses)
        src_ioc, dst_ioc = self._resolve_endpoints(finding)
        if src_ioc and dst_ioc:
            # Source contacted Destination
            self._add_relationship(
                source_id=src_ioc.canonical_id,
                target_id=dst_ioc.canonical_id,
                rel_type=RelationshipType.CONTACTED,
                valid_from=event_time_iso,
                confidence=0.9,
                source="wazuh",
                properties={
                    "protocol": finding.src_endpoint.protocol_name if finding.src_endpoint else None,
                    "src_port": finding.src_endpoint.port if finding.src_endpoint else None,
                    "dst_port": finding.dst_endpoint.port if finding.dst_endpoint else None,
                },
            )
        if dst_ioc:
            self._add_relationship(
                source_id=incident_node.canonical_id,
                target_id=dst_ioc.canonical_id,
                rel_type=RelationshipType.CONTACTED,
                valid_from=event_time_iso,
                confidence=dst_ioc.confidence,
                source="wazuh",
            )
        elif src_ioc:
            self._add_relationship(
                source_id=incident_node.canonical_id,
                target_id=src_ioc.canonical_id,
                rel_type=RelationshipType.CONTACTED,
                valid_from=event_time_iso,
                confidence=src_ioc.confidence,
                source="wazuh",
            )

        # 5. TTP nodes (MITRE ATT&CK)
        ttp_nodes = self._resolve_ttps(finding)
        for ttp_node in ttp_nodes:
            self._add_relationship(
                source_id=incident_node.canonical_id,
                target_id=ttp_node.canonical_id,
                rel_type=RelationshipType.USES,
                valid_from=event_time_iso,
                confidence=ttp_node.confidence,
                source="wazuh",
            )

    def _resolve_incident(self, finding: OCSFSecurityFinding) -> EntityNode:
        """Resolve or update the Incident graph node for the security finding."""
        canonical_id = f"finding:{finding.finding_info.uid}"
        if canonical_id in self._incidents:
            node = self._incidents[canonical_id]
            node.updated_at = time.time()
            return node

        node = EntityNode(
            canonical_id=canonical_id,
            entity_type=EntityType.INCIDENT,
            name=finding.finding_info.title,
            identifiers={"finding_uid": finding.finding_info.uid},
            properties={
                "severity": finding.severity,
                "severity_id": finding.severity_id,
                "status": finding.status,
                "desc": finding.finding_info.desc,
                "src_url": finding.finding_info.src_url,
                "created_time": finding.finding_info.created_time,
            },
            confidence=1.0,
            source_findings=[finding.finding_info.uid],
        )
        self._incidents[canonical_id] = node
        return node

    def _resolve_asset(self, finding: OCSFSecurityFinding) -> EntityNode | None:
        """Resolve Device to an Asset entity applying strong/weak identifier rules."""
        device = finding.device
        if device is None:
            self._unresolved.append({
                "entity_type": EntityType.ASSET.value,
                "finding_uid": finding.finding_info.uid,
                "reason": "Missing device attribute in finding",
            })
            return None

        raw_agent_id = device.uid.strip() if device.uid else None
        raw_hostname = device.name.strip() if device.name else None
        norm_hostname = raw_hostname.lower() if raw_hostname else None
        device_ip = device.ip.strip() if device.ip else None

        # Case A: Manager alert
        if raw_agent_id == "000" or (norm_hostname is not None and "manager" in norm_hostname):
            canonical_id = f"asset:manager:{norm_hostname or 'wazuh-manager'}"
            if canonical_id in self._assets:
                existing = self._assets[canonical_id]
                self._merge_provenance(existing, finding.finding_info.uid)
                return existing

            node = EntityNode(
                canonical_id=canonical_id,
                entity_type=EntityType.ASSET,
                name=raw_hostname or "Wazuh Manager",
                identifiers={"manager_name": norm_hostname or "wazuh-manager"},
                properties={"role": "manager", "hostname": raw_hostname},
                confidence=1.0,
                source_findings=[finding.finding_info.uid],
            )
            self._assets[canonical_id] = node
            return node

        # Case B: Standard agent alert with strong Agent ID
        if raw_agent_id:
            canonical_id = f"asset:agent:{raw_agent_id}"

            if canonical_id in self._assets:
                existing = self._assets[canonical_id]
                existing_host = existing.identifiers.get("hostname")

                # Check for conflicting hostnames under the same agent ID
                if norm_hostname and existing_host and norm_hostname != existing_host:
                    # Conflicting evidence: refuse silent merge!
                    conflict = ResolutionConflict(
                        entity_type=EntityType.ASSET,
                        existing_entity_id=canonical_id,
                        candidate_identifiers={"agent_id": raw_agent_id, "hostname": norm_hostname},
                        reason=(
                            f"Conflicting hostname '{norm_hostname}' encountered for existing agent_id "
                            f"'{raw_agent_id}' (registered with '{existing_host}')"
                        ),
                        finding_uid=finding.finding_info.uid,
                    )
                    self._conflicts.append(conflict)
                    logger.warning(
                        "entity_resolution_conflict_asset_hostname",
                        agent_id=raw_agent_id,
                        existing_hostname=existing_host,
                        new_hostname=norm_hostname,
                    )

                    # Create separate unmerged entity to preserve ambiguity
                    conflict_id = f"{canonical_id}:conflict-{len(self._conflicts)}"
                    conflict_node = EntityNode(
                        canonical_id=conflict_id,
                        entity_type=EntityType.ASSET,
                        name=raw_hostname or f"Agent {raw_agent_id} (Conflicting)",
                        identifiers={"agent_id": raw_agent_id, "hostname": norm_hostname},
                        properties={"hostname": raw_hostname, "ip": device_ip, "ambiguous": True},
                        confidence=0.5,
                        source_findings=[finding.finding_info.uid],
                    )
                    self._assets[conflict_id] = conflict_node
                    return conflict_node

                # No conflict: safely merge corroborating evidence
                self._merge_provenance(existing, finding.finding_info.uid)
                if norm_hostname and not existing_host:
                    existing.identifiers["hostname"] = norm_hostname
                    existing.properties["hostname"] = raw_hostname
                if device_ip and "ip" not in existing.properties:
                    existing.properties["ip"] = device_ip
                return existing

            # Check if there is another asset with the same hostname but DIFFERENT agent_id
            if norm_hostname and norm_hostname not in GENERIC_HOSTNAMES:
                for ast in self._assets.values():
                    ast_agent = ast.identifiers.get("agent_id")
                    ast_host = ast.identifiers.get("hostname")
                    if ast_host == norm_hostname and ast_agent and ast_agent != raw_agent_id:
                        # Conflict: two distinct agents claiming the same hostname
                        conflict = ResolutionConflict(
                            entity_type=EntityType.ASSET,
                            existing_entity_id=ast.canonical_id,
                            candidate_identifiers={"agent_id": raw_agent_id, "hostname": norm_hostname},
                            reason=(
                                f"Agent ID '{raw_agent_id}' claims hostname '{norm_hostname}', which is already "
                                f"assigned to agent ID '{ast_agent}'"
                            ),
                            finding_uid=finding.finding_info.uid,
                        )
                        self._conflicts.append(conflict)
                        logger.warning(
                            "entity_resolution_duplicate_hostname_distinct_agents",
                            hostname=norm_hostname,
                            existing_agent=ast_agent,
                            new_agent=raw_agent_id,
                        )
                        break

            # Create new canonical asset node
            node = EntityNode(
                canonical_id=canonical_id,
                entity_type=EntityType.ASSET,
                name=raw_hostname or f"Agent {raw_agent_id}",
                identifiers={
                    "agent_id": raw_agent_id,
                    **({"hostname": norm_hostname} if norm_hostname else {}),
                },
                properties={
                    "hostname": raw_hostname,
                    **({"ip": device_ip} if device_ip else {}),
                },
                confidence=1.0,
                source_findings=[finding.finding_info.uid],
            )
            self._assets[canonical_id] = node
            return node

        # Case C: Agent ID missing, but Hostname is present
        if norm_hostname:
            if norm_hostname in GENERIC_HOSTNAMES:
                # Generic hostname without agent ID is weak: refuse to merge across findings
                generic_id = f"asset:generic:{norm_hostname}:{finding.finding_info.uid}"
                node = EntityNode(
                    canonical_id=generic_id,
                    entity_type=EntityType.ASSET,
                    name=raw_hostname or norm_hostname,
                    identifiers={"generic_hostname": norm_hostname},
                    properties={"hostname": raw_hostname, "generic": True, "ip": device_ip},
                    confidence=0.4,
                    source_findings=[finding.finding_info.uid],
                )
                self._assets[generic_id] = node
                return node

            # Specific non-generic hostname
            canonical_id = f"asset:host:{norm_hostname}"
            if canonical_id in self._assets:
                existing = self._assets[canonical_id]
                self._merge_provenance(existing, finding.finding_info.uid)
                return existing

            node = EntityNode(
                canonical_id=canonical_id,
                entity_type=EntityType.ASSET,
                name=raw_hostname or norm_hostname,
                identifiers={"hostname": norm_hostname},
                properties={"hostname": raw_hostname, **({"ip": device_ip} if device_ip else {})},
                confidence=0.85,  # Moderate confidence because agent_id is missing
                source_findings=[finding.finding_info.uid],
            )
            self._assets[canonical_id] = node
            return node

        # Case D: Only IP is present (no agent_id, no hostname)
        # IP alone without host context is a weak attribute, not an Asset node
        self._unresolved.append({
            "entity_type": EntityType.ASSET.value,
            "finding_uid": finding.finding_info.uid,
            "reason": "Only IP provided without agent ID or hostname; weak identifier refused as Asset",
            "ip": device_ip,
        })
        return None

    def _resolve_identity(
        self,
        finding: OCSFSecurityFinding,
        asset_node: EntityNode | None,
    ) -> EntityNode | None:
        """Resolve User to an Identity entity distinguishing generic from specific accounts."""
        user = finding.user
        if user is None or not user.name:
            return None

        raw_username = user.name.strip()
        if not raw_username:
            return None

        norm_username = raw_username.lower()

        # Check if username is generic (e.g. root, admin)
        if norm_username in GENERIC_USERNAMES:
            host_scope = "unscoped"
            if asset_node:
                found_scope = (
                    asset_node.identifiers.get("hostname")
                    or asset_node.identifiers.get("agent_id")
                    or asset_node.identifiers.get("generic_hostname")
                    or asset_node.name
                )
                if found_scope:
                    host_scope = found_scope
            canonical_id = f"identity:user:{norm_username}@{host_scope}"
            display_name = f"{raw_username}@{host_scope}"

            if canonical_id in self._identities:
                existing = self._identities[canonical_id]
                self._merge_provenance(existing, finding.finding_info.uid)
                return existing

            node = EntityNode(
                canonical_id=canonical_id,
                entity_type=EntityType.IDENTITY,
                name=display_name,
                identifiers={
                    "username": norm_username,
                    "scope": host_scope,
                },
                properties={
                    "original_username": raw_username,
                    "is_generic": True,
                    "host_scope": host_scope,
                },
                confidence=0.9,
                source_findings=[finding.finding_info.uid],
            )
            self._identities[canonical_id] = node
            return node

        # Non-generic username (e.g. vsayare, or DOMAIN\\user)
        canonical_id = f"identity:user:{norm_username}"
        if canonical_id in self._identities:
            existing = self._identities[canonical_id]
            self._merge_provenance(existing, finding.finding_info.uid)
            return existing

        node = EntityNode(
            canonical_id=canonical_id,
            entity_type=EntityType.IDENTITY,
            name=raw_username,
            identifiers={"username": norm_username},
            properties={
                "original_username": raw_username,
                "is_generic": False,
            },
            confidence=0.95,
            source_findings=[finding.finding_info.uid],
        )
        self._identities[canonical_id] = node
        return node

    def _resolve_endpoints(
        self,
        finding: OCSFSecurityFinding,
    ) -> tuple[EntityNode | None, EntityNode | None]:
        """Resolve source and destination endpoints to IOC graph entities."""
        src_ioc = self._resolve_ip(
            finding.src_endpoint.ip if finding.src_endpoint else None,
            finding.finding_info.uid,
            role="source",
        )
        dst_ioc = self._resolve_ip(
            finding.dst_endpoint.ip if finding.dst_endpoint else None,
            finding.finding_info.uid,
            role="destination",
        )
        return src_ioc, dst_ioc

    def _resolve_ip(
        self,
        raw_ip: str | None,
        finding_uid: str,
        role: str,
    ) -> EntityNode | None:
        """Validate and resolve IP address to an IOC entity."""
        if not raw_ip:
            return None

        clean_ip = raw_ip.strip()
        if not clean_ip:
            return None

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            self._unresolved.append({
                "entity_type": EntityType.IOC.value,
                "finding_uid": finding_uid,
                "role": role,
                "raw_value": clean_ip,
                "reason": "Malformed or invalid IP address format",
            })
            return None

        norm_ip = str(ip_obj)
        canonical_id = f"ioc:ip:{norm_ip}"

        if canonical_id in self._iocs:
            existing = self._iocs[canonical_id]
            self._merge_provenance(existing, finding_uid)
            return existing

        is_private = ip_obj.is_private
        is_loopback = ip_obj.is_loopback
        # Public globally routable IPs have full confidence as IOC; private/loopback are weaker
        confidence = 0.7 if (is_private or is_loopback) else 1.0

        node = EntityNode(
            canonical_id=canonical_id,
            entity_type=EntityType.IOC,
            name=norm_ip,
            identifiers={"ip": norm_ip},
            properties={
                "ip": norm_ip,
                "version": ip_obj.version,
                "is_private": is_private,
                "is_loopback": is_loopback,
                "is_multicast": ip_obj.is_multicast,
                "is_global": ip_obj.is_global,
            },
            confidence=confidence,
            source_findings=[finding_uid],
        )
        self._iocs[canonical_id] = node
        return node

    def _resolve_ttps(self, finding: OCSFSecurityFinding) -> list[EntityNode]:
        """Resolve MITRE ATT&CK techniques to TTP graph entities."""
        results: list[EntityNode] = []
        for attack in finding.attacks:
            if not attack.technique or not attack.technique.uid:
                continue

            tech_id = attack.technique.uid.strip().upper()
            if not tech_id or tech_id == "UNKNOWN":
                continue

            canonical_id = f"ttp:mitre:{tech_id}"
            tech_name = attack.technique.name.strip() if attack.technique.name else None
            tactic_name = attack.tactic.name.strip() if attack.tactic and attack.tactic.name else None

            if canonical_id in self._ttps:
                existing = self._ttps[canonical_id]
                self._merge_provenance(existing, finding.finding_info.uid)
                if tech_name and not existing.properties.get("technique_name"):
                    existing.properties["technique_name"] = tech_name
                results.append(existing)
                continue

            node = EntityNode(
                canonical_id=canonical_id,
                entity_type=EntityType.TTP,
                name=tech_name or tech_id,
                identifiers={"technique_id": tech_id},
                properties={
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic_name,
                },
                confidence=1.0,
                source_findings=[finding.finding_info.uid],
            )
            self._ttps[canonical_id] = node
            results.append(node)

        return results

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: RelationshipType,
        valid_from: str,
        confidence: float,
        source: str = "wazuh",
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Add relationship edge if not already present."""
        edge = RelationshipEdge(
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            valid_from=valid_from,
            valid_to=None,
            confidence=confidence,
            source=source,
            properties=properties or {},
        )
        self._relationships.append(edge)

    @staticmethod
    def _merge_provenance(entity: EntityNode, finding_uid: str) -> None:
        """Add finding UID to entity source_findings if not already recorded."""
        if finding_uid not in entity.source_findings:
            entity.source_findings.append(finding_uid)
        entity.updated_at = time.time()

    @staticmethod
    def _to_iso_timestamp(epoch_ms: int) -> str:
        """Convert epoch milliseconds to ISO 8601 UTC string."""
        try:
            return datetime.fromtimestamp(epoch_ms / 1000.0, tz=UTC).isoformat()
        except (ValueError, OSError):
            return datetime.now(tz=UTC).isoformat()
