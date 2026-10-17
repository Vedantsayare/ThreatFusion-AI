"""
tests/unit/test_entity_resolution.py — Comprehensive unit tests for Entity Resolution.

Verifies:
- Entity extraction from normalized findings (Asset, Identity, IOC, TTP, Incident).
- Duplicate entity deduplication and merging with provenance tracking.
- Case normalization for hostnames, usernames, and MITRE technique IDs.
- Conflict detection and merge refusal on conflicting hostnames or agent IDs.
- Scoping of generic usernames (e.g. root, admin) by host to prevent false merges.
- Handling of weak attributes (generic hostnames, private IPs).
- Graceful handling of missing fields and malformed IP addresses.
- Determinism and repeatability of resolution results.
- Safe handling of untrusted injection strings in telemetry.
- Graph ingestion readiness and presence of required edge properties (valid_from, valid_to, confidence, source).
"""

from __future__ import annotations

import pytest

from graph.models import (
    EntityType,
    RelationshipType,
    ResolutionResult,
)
from graph.resolver import EntityResolver
from normalization.models import (
    OCSFAttack,
    OCSFDevice,
    OCSFEndpoint,
    OCSFFindingInfo,
    OCSFMetadata,
    OCSFProduct,
    OCSFSecurityFinding,
    OCSFTactic,
    OCSFTechnique,
    OCSFUser,
)


def make_finding(
    uid: str = "find-1",
    time_ms: int = 1700000000000,
    severity_id: int = 4,
    severity: str = "High",
    title: str = "Suspicious SSH activity",
    agent_id: str | None = "001",
    agent_name: str | None = "web-server-01",
    agent_ip: str | None = "192.168.1.50",
    username: str | None = "admin",
    src_ip: str | None = "203.0.113.195",
    src_port: int | None = 45123,
    dst_ip: str | None = "192.168.1.50",
    dst_port: int | None = 22,
    technique_id: str | None = "T1110",
    technique_name: str | None = "Brute Force",
    tactic_name: str | None = "Credential Access",
) -> OCSFSecurityFinding:
    """Helper to construct typed OCSFSecurityFinding instances for testing."""
    device = (
        OCSFDevice(name=agent_name, uid=agent_id, ip=agent_ip, type_id=0)
        if (agent_id or agent_name or agent_ip)
        else None
    )
    src_endpoint = (
        OCSFEndpoint(ip=src_ip, port=src_port, protocol_name="ssh")
        if (src_ip or src_port is not None)
        else None
    )
    dst_endpoint = (
        OCSFEndpoint(ip=dst_ip, port=dst_port, protocol_name="ssh")
        if (dst_ip or dst_port is not None)
        else None
    )
    user = OCSFUser(name=username) if username else None

    attacks: list[OCSFAttack] = []
    if technique_id:
        attacks.append(
            OCSFAttack(
                tactic=OCSFTactic(name=tactic_name) if tactic_name else None,
                technique=OCSFTechnique(uid=technique_id, name=technique_name),
            )
        )

    return OCSFSecurityFinding(
        class_uid=2001,
        class_name="Security Finding",
        category_uid=2,
        category_name="Findings",
        activity_id=1,
        activity_name="Create",
        severity_id=severity_id,
        severity=severity,
        status_id=1,
        status="New",
        time=time_ms,
        metadata=OCSFMetadata(
            version="1.1.0",
            schema_name="project_ocsf_subset",
            product=OCSFProduct(name="Wazuh", vendor_name="Wazuh"),
            original_time="2026-10-17T12:00:00Z",
        ),
        finding_info=OCSFFindingInfo(
            uid=uid,
            title=title,
            desc=title,
            types=["syslog", "sshd"],
            created_time=time_ms,
        ),
        device=device,
        src_endpoint=src_endpoint,
        dst_endpoint=dst_endpoint,
        user=user,
        attacks=attacks,
        message=title,
        raw_data={"id": uid},
    )


@pytest.fixture
def resolver() -> EntityResolver:
    return EntityResolver()


class TestEntityExtractionAndGraphStructure:
    """Tests basic extraction and graph representation for a complete finding."""

    def test_complete_finding_extraction(self, resolver: EntityResolver) -> None:
        finding = make_finding()
        result = resolver.resolve_finding(finding)

        assert isinstance(result, ResolutionResult)
        # Check node types present
        entities = result.entities
        assert "finding:find-1" in entities
        assert "asset:agent:001" in entities
        assert "identity:user:admin@web-server-01" in entities
        assert "ioc:ip:203.0.113.195" in entities
        assert "ioc:ip:192.168.1.50" in entities
        assert "ttp:mitre:T1110" in entities

        # Verify edge generation
        rel_types = [rel.rel_type for rel in result.relationships]
        assert RelationshipType.AFFECTS in rel_types
        assert RelationshipType.INVOLVES in rel_types
        assert RelationshipType.CONTACTED in rel_types
        assert RelationshipType.USES in rel_types

        # Verify required edge properties (valid_from, valid_to, confidence, source)
        for rel in result.relationships:
            assert rel.valid_from is not None
            assert rel.valid_to is None
            assert 0.0 <= rel.confidence <= 1.0
            assert rel.source == "wazuh"

        # Verify serialization helpers
        graph_params = result.to_cypher_parameters()
        assert "nodes" in graph_params
        assert "edges" in graph_params
        assert len(graph_params["nodes"]) == len(entities)
        assert len(graph_params["edges"]) == len(result.relationships)


class TestDuplicateEntitiesAndDeduplication:
    """Tests merging of identical entities across multiple findings."""

    def test_duplicate_agent_findings_merge_into_single_asset(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding1 = make_finding(uid="f-1", agent_id="001", agent_name="web-server-01")
        finding2 = make_finding(uid="f-2", agent_id="001", agent_name="web-server-01")

        result = resolver.resolve_findings([finding1, finding2])

        # Exactly 1 Asset node exists
        asset_nodes = [e for e in result.entities.values() if e.entity_type == EntityType.ASSET]
        assert len(asset_nodes) == 1
        asset = asset_nodes[0]
        assert asset.canonical_id == "asset:agent:001"
        assert "f-1" in asset.source_findings
        assert "f-2" in asset.source_findings

    def test_duplicate_ioc_ip_merges_across_findings(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding1 = make_finding(uid="f-1", src_ip="203.0.113.195")
        finding2 = make_finding(uid="f-2", src_ip="203.0.113.195")

        result = resolver.resolve_findings([finding1, finding2])

        ioc_nodes = [
            e for e in result.entities.values()
            if e.entity_type == EntityType.IOC and e.canonical_id == "ioc:ip:203.0.113.195"
        ]
        assert len(ioc_nodes) == 1
        assert "f-1" in ioc_nodes[0].source_findings
        assert "f-2" in ioc_nodes[0].source_findings

    def test_duplicate_ttp_merges_across_findings(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding1 = make_finding(uid="f-1", technique_id="T1110", technique_name="Brute Force")
        finding2 = make_finding(uid="f-2", technique_id="T1110", technique_name="Brute Force")

        result = resolver.resolve_findings([finding1, finding2])

        ttp_nodes = [e for e in result.entities.values() if e.entity_type == EntityType.TTP]
        assert len(ttp_nodes) == 1
        assert ttp_nodes[0].canonical_id == "ttp:mitre:T1110"
        assert "f-1" in ttp_nodes[0].source_findings
        assert "f-2" in ttp_nodes[0].source_findings


class TestCaseNormalization:
    """Tests case-insensitivity in matching while preserving original casing."""

    def test_hostname_case_normalization(self, resolver: EntityResolver) -> None:
        finding1 = make_finding(uid="f-1", agent_id="001", agent_name="WEB-SERVER-01")
        finding2 = make_finding(uid="f-2", agent_id="001", agent_name="web-server-01")

        result = resolver.resolve_findings([finding1, finding2])

        assets = [e for e in result.entities.values() if e.entity_type == EntityType.ASSET]
        assert len(assets) == 1
        assert assets[0].identifiers["hostname"] == "web-server-01"

    def test_username_case_normalization(self, resolver: EntityResolver) -> None:
        finding1 = make_finding(uid="f-1", username="JohnDoe", agent_name="srv-01")
        finding2 = make_finding(uid="f-2", username="johndoe", agent_name="srv-01")

        result = resolver.resolve_findings([finding1, finding2])

        identities = [e for e in result.entities.values() if e.entity_type == EntityType.IDENTITY]
        assert len(identities) == 1
        assert identities[0].canonical_id == "identity:user:johndoe"
        assert identities[0].identifiers["username"] == "johndoe"

    def test_mitre_technique_case_normalization(self, resolver: EntityResolver) -> None:
        finding1 = make_finding(uid="f-1", technique_id="t1110")
        finding2 = make_finding(uid="f-2", technique_id="T1110")

        result = resolver.resolve_findings([finding1, finding2])

        ttps = [e for e in result.entities.values() if e.entity_type == EntityType.TTP]
        assert len(ttps) == 1
        assert ttps[0].canonical_id == "ttp:mitre:T1110"


class TestConflictingIdentifiersAndAmbiguity:
    """Tests conflict detection and refusal to merge conflicting or ambiguous entities."""

    def test_conflicting_hostnames_for_same_agent_id_refuses_merge(
        self,
        resolver: EntityResolver,
    ) -> None:
        # Agent 001 originally associated with web-server-01
        finding1 = make_finding(uid="f-1", agent_id="001", agent_name="web-server-01")
        # Same agent ID 001 claiming to be db-server-02
        finding2 = make_finding(uid="f-2", agent_id="001", agent_name="db-server-02")

        result = resolver.resolve_findings([finding1, finding2])

        # Merge is refused: 2 separate Asset entities are retained
        assets = [e for e in result.entities.values() if e.entity_type == EntityType.ASSET]
        assert len(assets) == 2
        # Conflict is explicitly reported
        assert len(result.conflicts) == 1
        assert result.conflicts[0].entity_type == EntityType.ASSET
        assert "Conflicting hostname" in result.conflicts[0].reason

    def test_distinct_agents_claiming_same_hostname_reports_conflict(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding1 = make_finding(uid="f-1", agent_id="001", agent_name="shared-host-name")
        finding2 = make_finding(uid="f-2", agent_id="002", agent_name="shared-host-name")

        result = resolver.resolve_findings([finding1, finding2])

        # Preserved as 2 distinct assets under their respective strong agent IDs
        assert "asset:agent:001" in result.entities
        assert "asset:agent:002" in result.entities
        # Conflict flagged
        assert len(result.conflicts) == 1
        assert "already assigned to agent" in result.conflicts[0].reason

    def test_generic_usernames_are_scoped_to_prevent_cross_host_merge(
        self,
        resolver: EntityResolver,
    ) -> None:
        # "root" on web-server-01 vs "root" on db-server-02
        finding1 = make_finding(uid="f-1", username="root", agent_id="001", agent_name="web-server-01")
        finding2 = make_finding(uid="f-2", username="root", agent_id="002", agent_name="db-server-02")

        result = resolver.resolve_findings([finding1, finding2])

        identities = [e for e in result.entities.values() if e.entity_type == EntityType.IDENTITY]
        # Must NOT be merged into a single generic "identity:user:root"!
        assert len(identities) == 2
        ids = {i.canonical_id for i in identities}
        assert "identity:user:root@web-server-01" in ids
        assert "identity:user:root@db-server-02" in ids

    def test_generic_hostname_without_agent_id_is_not_merged(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding1 = make_finding(uid="f-1", agent_id=None, agent_name="localhost")
        finding2 = make_finding(uid="f-2", agent_id=None, agent_name="localhost")

        result = resolver.resolve_findings([finding1, finding2])

        # Generic hostname without corroborating agent ID must not be merged
        assets = [e for e in result.entities.values() if e.entity_type == EntityType.ASSET]
        assert len(assets) == 2
        for a in assets:
            assert "generic" in a.canonical_id
            assert a.confidence < 0.5


class TestMissingFieldsAndInvalidData:
    """Tests resilience on missing, empty, or invalid fields."""

    def test_missing_device_records_unresolved_entry(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding = make_finding(agent_id=None, agent_name=None, agent_ip=None)
        result = resolver.resolve_finding(finding)

        assert not any(e.entity_type == EntityType.ASSET for e in result.entities.values())
        assert len(result.unresolved) >= 1
        assert result.unresolved[0]["entity_type"] == "Asset"

    def test_missing_user_creates_no_identity(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding = make_finding(username=None)
        result = resolver.resolve_finding(finding)

        assert not any(e.entity_type == EntityType.IDENTITY for e in result.entities.values())

    def test_invalid_ip_format_records_unresolved(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding = make_finding(src_ip="999.999.999.999")
        result = resolver.resolve_finding(finding)

        unresolved_iocs = [u for u in result.unresolved if u["entity_type"] == "IOC"]
        assert len(unresolved_iocs) == 1
        assert "Malformed or invalid IP" in unresolved_iocs[0]["reason"]

    def test_private_ip_marked_with_reduced_confidence(
        self,
        resolver: EntityResolver,
    ) -> None:
        finding = make_finding(src_ip="192.168.1.100")
        result = resolver.resolve_finding(finding)

        ioc = result.entities["ioc:ip:192.168.1.100"]
        assert ioc.properties["is_private"] is True
        assert ioc.confidence == 0.7  # RFC 1918 private IP has reduced confidence


class TestDeterminismAndUntrustedInput:
    """Tests repeatability and safe untrusted input handling."""

    def test_deterministic_resolution_results(
        self,
        resolver: EntityResolver,
    ) -> None:
        findings = [
            make_finding(uid=f"f-{i}", agent_id=f"00{i % 2 + 1}")
            for i in range(5)
        ]
        res1 = resolver.resolve_findings(findings)

        # Reset and resolve again
        resolver.reset()
        res2 = resolver.resolve_findings(findings)

        assert set(res1.entities.keys()) == set(res2.entities.keys())
        assert len(res1.relationships) == len(res2.relationships)
        assert len(res1.conflicts) == len(res2.conflicts)

    def test_malicious_telemetry_strings_preserved_as_passive_data(
        self,
        resolver: EntityResolver,
    ) -> None:
        dangerous_user = "admin'; DROP TABLE nodes; --"
        dangerous_host = "web-server<script>alert(1)</script>"
        finding = make_finding(
            username=dangerous_user,
            agent_name=dangerous_host,
            title="MATCH (n) DETACH DELETE n",
        )
        result = resolver.resolve_finding(finding)

        # Confirm strings preserved verbatim without execution
        incident = result.entities["finding:find-1"]
        assert incident.name == "MATCH (n) DETACH DELETE n"

        identity = result.entities[f"identity:user:{dangerous_user.lower()}"]
        assert identity.properties["original_username"] == dangerous_user

        asset = result.entities["asset:agent:001"]
        assert asset.properties["hostname"] == dangerous_host
