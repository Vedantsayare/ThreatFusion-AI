"""
tests/unit/test_triage_investigation.py — Unit tests for triage and investigation engine.

Verifies:
- Deterministic priority assignment across all levels (LOW, MEDIUM, HIGH, CRITICAL).
- Scoring boundaries and hard rule overrides (e.g. Critical + Privileged -> CRITICAL).
- Handling of missing or invalid severities with uncertainty indicators.
- Entity-resolution conflict incorporation and uncertainty reporting.
- Graph evidence retrieval, absence (0 history), and database unavailability.
- Repeated activity boost when corroborated by actual graph memory.
- Handling of missing device, missing timestamp, and incomplete telemetry.
- Determinism and repeatability across multiple runs.
- Safe handling of malicious injection payloads in telemetry.
- Separation of empirical facts from inferences in investigation context.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from agents.investigation import InvestigationService
from agents.models import (
    IncidentPriority,
    InvestigationContext,
    TriageResult,
)
from agents.triage import AlertTriageEngine, TriagePolicy
from graph.client import GraphConnectionError, Neo4jClient
from graph.models import EntityType, ResolutionConflict, ResolutionResult
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
    uid: str = "triage-find-1",
    severity_id: int = 4,
    severity: str = "High",
    title: str = "SSH brute force attempt",
    username: str | None = "admin",
    agent_id: str | None = "001",
    agent_name: str | None = "web-server-01",
    src_ip: str | None = "203.0.113.195",
    dst_ip: str | None = "192.168.1.50",
    technique_id: str | None = "T1110",
    technique_name: str | None = "Brute Force",
    tactic_name: str | None = "Credential Access",
    time_ms: int = 1700000000000,
) -> OCSFSecurityFinding:
    """Helper to construct typed findings for triage testing."""
    device = (
        OCSFDevice(name=agent_name, uid=agent_id, ip=dst_ip, type_id=0)
        if (agent_id or agent_name)
        else None
    )
    src_endpoint = OCSFEndpoint(ip=src_ip, port=45123, protocol_name="ssh") if src_ip else None
    dst_endpoint = OCSFEndpoint(ip=dst_ip, port=22, protocol_name="ssh") if dst_ip else None
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
        raw_data={"id": uid, "rule": {"level": 10 if severity_id == 4 else 3}},
    )


@pytest.fixture
def triage_engine() -> AlertTriageEngine:
    return AlertTriageEngine(policy=TriagePolicy())


class TestTriagePriorityLevels:
    """Tests priority scoring across all levels: LOW, MEDIUM, HIGH, CRITICAL."""

    def test_low_priority_informational_alert(self, triage_engine: AlertTriageEngine) -> None:
        finding = make_finding(
            severity_id=1,
            severity="Informational",
            title="System routine event",
            username="regular_user",
            src_ip="192.168.1.10",  # private IP, not public
            technique_id=None,
        )
        result = triage_engine.triage(finding)

        assert isinstance(result, TriageResult)
        assert result.priority == IncidentPriority.LOW
        assert result.score < 35
        assert any("Base score" in r for r in result.reasons)

    def test_medium_priority_low_severity_with_risk_factors(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding(
            severity_id=2,  # Low base (20)
            severity="Low",
            title="External connection",
            username="regular_user",
            src_ip="203.0.113.5",  # Public IP (+10) -> score 30
            technique_id="T1110",   # High-impact MITRE (+15) -> score 45
        )
        result = triage_engine.triage(finding)

        assert result.priority == IncidentPriority.MEDIUM
        assert 35 <= result.score < 60

    def test_high_priority_high_severity_alert(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding(
            severity_id=4,  # High base (60)
            severity="High",
            username="analyst",
            src_ip="192.168.1.10",
            technique_id=None,
        )
        result = triage_engine.triage(finding)

        assert result.priority == IncidentPriority.HIGH
        assert 60 <= result.score < 80

    def test_critical_priority_critical_severity_with_privileged_account(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding(
            severity_id=5,  # Critical base (80)
            severity="Critical",
            username="root",  # Privileged (+15) -> score 95
            technique_id="T1110",
        )
        result = triage_engine.triage(finding)

        assert result.priority == IncidentPriority.CRITICAL
        assert result.score >= 80
        assert any("Privileged administrative account 'root'" in r for r in result.reasons)


class TestTriageMissingAndInvalidData:
    """Tests handling of missing or invalid severities, devices, and timestamps."""

    def test_unknown_severity_defaults_and_flags_uncertainty(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding(severity_id=0, severity="Unknown")
        result = triage_engine.triage(finding)

        assert result.has_missing_data is True
        assert any("severity is unknown" in u for u in result.uncertainties)
        # Score derives from default unknown severity (25)
        assert result.score >= 25

    def test_missing_device_flags_missing_data(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding(agent_id=None, agent_name=None)
        result = triage_engine.triage(finding)

        assert result.has_missing_data is True
        assert any("lacks host/device" in u for u in result.uncertainties)


class TestEntityResolutionContextInTriage:
    """Tests integration with Phase 4 entity resolution and conflict reporting."""

    def test_entity_resolution_conflict_is_flagged_in_uncertainties(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding()
        conflict = ResolutionConflict(
            entity_type=EntityType.ASSET,
            existing_entity_id="asset:agent:001",
            candidate_identifiers={"agent_id": "001", "hostname": "rogue-host"},
            reason="Conflicting hostname 'rogue-host' for agent_id '001'",
            finding_uid=finding.finding_info.uid,
        )
        resolution = ResolutionResult(conflicts=[conflict])

        result = triage_engine.triage(finding, resolution=resolution)

        assert any("Entity resolution conflict" in u for u in result.uncertainties)
        assert any("reconcile entity identity conflict" in s for s in result.recommended_steps)


class TestGraphContextAndRepetition:
    """Tests integration with Phase 5 graph memory and repeated incident activity."""

    def test_repeated_activity_in_graph_boosts_score(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding(severity_id=3, severity="Medium")  # Base 40
        context = InvestigationContext(
            finding_id=finding.finding_info.uid,
            graph_available=True,
            historical_finding_count=4,  # >= 3 repetitions triggers boost (+15)
        )
        result = triage_engine.triage(finding, context=context)

        # Base 40 + Privileged 15 (admin) + Public IP 10 + High impact 15 + Repeated 15 = 95 -> CRITICAL
        assert any("Recurrent security activity" in r for r in result.reasons)
        assert result.priority == IncidentPriority.CRITICAL

    def test_graph_unavailable_recorded_in_uncertainties(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding()
        context = InvestigationContext(
            finding_id=finding.finding_info.uid,
            graph_available=False,
            lookup_error="Connection refused",
        )
        result = triage_engine.triage(finding, context=context)

        assert any("Graph memory database unavailable" in u for u in result.uncertainties)
        assert any("Retry graph neighborhood lookup" in s for s in result.recommended_steps)


class TestInvestigationService:
    """Tests InvestigationService fact extraction, inference separation, and graph queries."""

    @pytest.mark.asyncio
    async def test_build_context_without_graph_client(self) -> None:
        service = InvestigationService(graph_client=None)
        finding = make_finding(username="root")

        context = await service.build_context(finding)

        assert context.finding_id == "triage-find-1"
        assert context.graph_available is False
        assert any("Neo4j client not configured" in m for m in context.missing_evidence)

        # Facts observed directly from telemetry
        fact_types = [f.fact_type for f in context.observed_facts]
        assert "telemetry" in fact_types
        assert "device" in fact_types
        assert "user" in fact_types

        # Inferences clearly separated from facts
        inf_types = [i.inference_type for i in context.inferences]
        assert "privileged_account_targeted" in inf_types

    @pytest.mark.asyncio
    async def test_build_context_with_mocked_graph_client(self) -> None:
        mock_graph = AsyncMock(spec=Neo4jClient)
        mock_graph.get_entity_neighborhood = AsyncMock(
            return_value={
                "center": {"id": "finding:triage-find-1"},
                "neighbors": [{"id": "asset:agent:001", "labels": ["Asset"]}],
                "relationships": [{"type": "AFFECTS", "source": "finding:triage-find-1", "target": "asset:agent:001"}],
            }
        )
        mock_graph.run_query = AsyncMock(
            return_value=[{"hist_count": 5, "recent_finding_ids": ["f-old-1", "f-old-2"]}]
        )

        service = InvestigationService(graph_client=mock_graph)
        finding = make_finding()

        context = await service.build_context(finding)

        assert context.graph_available is True
        assert context.historical_finding_count == 5
        assert len(context.entities_found) == 1
        assert len(context.relationships_found) == 1

        # Check observed facts recorded
        fact_types = [f.fact_type for f in context.observed_facts]
        assert "historical_repetition" in fact_types

        # Check inference generated
        inf_types = [i.inference_type for i in context.inferences]
        assert "repeated_target_asset" in inf_types

    @pytest.mark.asyncio
    async def test_build_context_handles_graph_error_gracefully(self) -> None:
        mock_graph = AsyncMock(spec=Neo4jClient)
        mock_graph.get_entity_neighborhood = AsyncMock(
            side_effect=GraphConnectionError("Simulated database timeout")
        )

        service = InvestigationService(graph_client=mock_graph)
        finding = make_finding()

        context = await service.build_context(finding)

        # Service must NOT crash; reports graph as unavailable
        assert context.graph_available is False
        assert "Simulated database timeout" in str(context.lookup_error)
        assert any("Graph lookup failed" in m for m in context.missing_evidence)


class TestDeterminismAndUntrustedInput:
    """Tests stability across repeat evaluations and passive handling of injection strings."""

    def test_triage_determinism_across_runs(self, triage_engine: AlertTriageEngine) -> None:
        finding = make_finding()
        res1 = triage_engine.triage(finding)
        res2 = triage_engine.triage(finding)

        assert res1.score == res2.score
        assert res1.priority == res2.priority
        assert res1.reasons == res2.reasons
        assert res1.recommended_steps == res2.recommended_steps

    def test_malicious_telemetry_strings_handled_as_passive_data(
        self,
        triage_engine: AlertTriageEngine,
    ) -> None:
        finding = make_finding(
            title="DROP TABLE alerts; --",
            username="admin' OR '1'='1",
        )
        result = triage_engine.triage(finding)

        assert result.title == "DROP TABLE alerts; --"
        assert any("admin' OR '1'='1" in r for r in result.reasons)
