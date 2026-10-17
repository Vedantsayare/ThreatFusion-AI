"""
agents/triage.py — Deterministic, rule-and-score-based alert triage engine.

Evaluates normalized OCSF findings, Phase 4 resolution evidence, and Phase 5
graph context to assign deterministic incident priorities (LOW, MEDIUM, HIGH, CRITICAL).
Treats missing data as unknown rather than safe and never calls external LLMs.
"""

from __future__ import annotations

import ipaddress
import re
import time

from agents.models import (
    EvidenceItem,
    IncidentPriority,
    InvestigationContext,
    TriageResult,
)
from core.logger import get_logger
from graph.models import ResolutionResult
from normalization.models import OCSFSecurityFinding

logger = get_logger("agents.triage")

# Privileged accounts that escalate incident risk when involved
PRIVILEGED_ACCOUNTS = frozenset({
    "root",
    "admin",
    "administrator",
    "system",
    "sudo",
    "domain admins",
    "operator",
})

# High-impact MITRE ATT&CK tactics and techniques
HIGH_IMPACT_TACTICS = frozenset({
    "Credential Access",
    "Execution",
    "Privilege Escalation",
    "Impact",
    "Exfiltration",
})

HIGH_IMPACT_TECHNIQUES = frozenset({
    "T1110",      # Brute Force
    "T1003",      # OS Credential Dumping
    "T1059",      # Command and Scripting Interpreter
    "T1078",      # Valid Accounts
    "T1053",      # Scheduled Task/Job
    "T1486",      # Data Encrypted for Impact (Ransomware)
    "T1021",      # Remote Services
    "T1190",      # Exploit Public-Facing Application
})


class TriagePolicy:
    """Configurable scoring weights and priority thresholds for alert triage."""

    def __init__(
        self,
        base_severity_scores: dict[int, int] | None = None,
        privileged_account_boost: int = 15,
        public_ip_boost: int = 10,
        high_impact_mitre_boost: int = 15,
        repeated_activity_threshold: int = 3,
        repeated_activity_boost: int = 15,
        high_repetition_threshold: int = 5,
        high_repetition_boost: int = 20,
    ) -> None:
        self.base_severity_scores = base_severity_scores or {
            5: 80,  # Critical
            4: 60,  # High
            3: 40,  # Medium
            2: 20,  # Low
            1: 10,  # Informational
            0: 25,  # Unknown / Missing
        }
        self.privileged_account_boost = privileged_account_boost
        self.public_ip_boost = public_ip_boost
        self.high_impact_mitre_boost = high_impact_mitre_boost
        self.repeated_activity_threshold = repeated_activity_threshold
        self.repeated_activity_boost = repeated_activity_boost
        self.high_repetition_threshold = high_repetition_threshold
        self.high_repetition_boost = high_repetition_boost


class AlertTriageEngine:
    """Deterministic triage engine mapping findings and context to incident priorities."""

    def __init__(self, policy: TriagePolicy | None = None) -> None:
        self.policy = policy or TriagePolicy()

    def triage(
        self,
        finding: OCSFSecurityFinding,
        resolution: ResolutionResult | None = None,
        context: InvestigationContext | None = None,
    ) -> TriageResult:
        """Evaluate a normalized security finding and compute its deterministic triage priority.

        Args:
            finding: Normalized OCSF security finding.
            resolution: Optional Phase 4 resolution result.
            context: Optional Phase 5 investigation context from Neo4j.

        Returns:
            TriageResult: Strongly typed priority, score, reasons, evidence, and recommendations.
        """
        finding_id = finding.finding_info.uid
        reasons: list[str] = []
        evidence: list[EvidenceItem] = []
        mitre_techniques: list[str] = []
        uncertainties: list[str] = []
        has_missing_data = False

        # 1. Base Score from OCSF Severity
        sev_id = finding.severity_id
        base_score = self.policy.base_severity_scores.get(sev_id, 25)
        score = base_score

        reasons.append(
            f"Base score {base_score} derived from OCSF severity '{finding.severity}' (level {sev_id})"
        )
        evidence.append(
            EvidenceItem(
                source="ocsf_normalization",
                evidence_type="severity_assessment",
                detail=f"{finding.severity} (level {sev_id})",
                confidence=1.0,
                timestamp=finding.metadata.original_time,
                data={"severity_id": sev_id, "severity": finding.severity},
            )
        )

        if sev_id == 0:
            has_missing_data = True
            uncertainties.append("Original alert severity is unknown or unmapped; assigned baseline default")

        # 2. Privileged Account Factor
        is_privileged = False
        if finding.user is not None and finding.user.name:
            username_clean = finding.user.name.strip().lower()
            # Match exact account name or first token delimited by punctuation/whitespace
            first_token = re.split(r"['\"\s:@\\]+", username_clean)[0]
            if username_clean in PRIVILEGED_ACCOUNTS or first_token in PRIVILEGED_ACCOUNTS:
                is_privileged = True
                score += self.policy.privileged_account_boost
                reasons.append(
                    f"Privileged administrative account '{finding.user.name}' involved "
                    f"(+{self.policy.privileged_account_boost})"
                )
                evidence.append(
                    EvidenceItem(
                        source="identity_telemetry",
                        evidence_type="privileged_account",
                        detail=finding.user.name,
                        confidence=1.0,
                        data={"username": finding.user.name},
                    )
                )

        # 3. External / Public IP Exposure Factor
        has_public_ip = False
        for endpoint, role in (
            (finding.src_endpoint, "source"),
            (finding.dst_endpoint, "destination"),
        ):
            if endpoint and endpoint.ip:
                ip_clean = endpoint.ip.strip()
                if self._is_public_ip(ip_clean):
                    has_public_ip = True
                    score += self.policy.public_ip_boost
                    reasons.append(
                        f"External/public IP address involved in {role} role ({ip_clean}) "
                        f"(+{self.policy.public_ip_boost})"
                    )
                    evidence.append(
                        EvidenceItem(
                            source="network_telemetry",
                            evidence_type="public_ip_exposure",
                            detail=f"{role}: {ip_clean}",
                            confidence=1.0,
                            data={"ip": ip_clean, "role": role},
                        )
                    )
                    break  # Boost applied once per finding for public IP exposure

        # 4. High-Impact MITRE ATT&CK Techniques
        has_high_impact_mitre = False
        for attack in finding.attacks:
            if attack.technique and attack.technique.uid:
                t_id = attack.technique.uid.upper().strip()
                t_base = t_id.split(".")[0]  # e.g. T1110 from T1110.001
                mitre_techniques.append(t_id)

                tactic_name = attack.tactic.name if attack.tactic else ""
                is_high_impact = (
                    t_base in HIGH_IMPACT_TECHNIQUES
                    or tactic_name in HIGH_IMPACT_TACTICS
                )

                if is_high_impact and not has_high_impact_mitre:
                    has_high_impact_mitre = True
                    score += self.policy.high_impact_mitre_boost
                    desc_str = f" ({attack.technique.name})" if attack.technique.name else ""
                    reasons.append(
                        f"High-impact MITRE ATT&CK technique {t_id}{desc_str} detected "
                        f"(+{self.policy.high_impact_mitre_boost})"
                    )
                    evidence.append(
                        EvidenceItem(
                            source="mitre_mapping",
                            evidence_type="high_impact_technique",
                            detail=t_id,
                            confidence=1.0,
                            data={"technique_id": t_id, "tactic": tactic_name},
                        )
                    )

        # 5. Entity Resolution Conflicts and Uncertainty
        if resolution is not None:
            if resolution.conflicts:
                for conflict in resolution.conflicts:
                    uncertainties.append(f"Entity resolution conflict: {conflict.reason}")
            if resolution.unresolved:
                has_missing_data = True
                for unres in resolution.unresolved:
                    uncertainties.append(f"Unresolved {unres.get('entity_type')}: {unres.get('reason')}")

        # 6. Graph Context & Historical Repetition
        if context is not None:
            if not context.graph_available:
                uncertainties.append("Graph memory database unavailable; historical correlation skipped")
            elif context.historical_finding_count >= self.policy.repeated_activity_threshold:
                hist_count = context.historical_finding_count
                boost = (
                    self.policy.high_repetition_boost
                    if hist_count >= self.policy.high_repetition_threshold
                    else self.policy.repeated_activity_boost
                )
                score += boost
                reasons.append(
                    f"Recurrent security activity on asset: {hist_count} previous incident(s) "
                    f"recorded in graph memory (+{boost})"
                )
                evidence.append(
                    EvidenceItem(
                        source="neo4j_graph",
                        evidence_type="historical_repetition",
                        detail=f"{hist_count} prior incidents",
                        confidence=0.9,
                        data={"historical_count": hist_count},
                    )
                )

        # 7. Check Missing Attributes in Telemetry
        if finding.device is None:
            has_missing_data = True
            uncertainties.append("Alert lacks host/device attribution")
        if finding.metadata.original_time is None or finding.unmapped.get("timestamp_warning"):
            has_missing_data = True
            uncertainties.append("Event timestamp missing or defaulted from system clock")

        # 8. Bounded Score Calculation & Priority Assignment
        score = max(0, min(100, score))
        priority = self._score_to_priority(
            score=score,
            sev_id=sev_id,
            is_privileged=is_privileged,
            has_high_impact_mitre=has_high_impact_mitre,
            has_public_ip=has_public_ip,
            context=context,
        )

        # 9. Generate Recommended Advisory Investigation Steps
        recommended_steps = self._generate_recommendations(
            finding=finding,
            priority=priority,
            is_privileged=is_privileged,
            has_public_ip=has_public_ip,
            has_high_impact_mitre=has_high_impact_mitre,
            resolution=resolution,
            context=context,
        )

        return TriageResult(
            finding_id=finding_id,
            title=finding.finding_info.title,
            priority=priority,
            score=score,
            severity=finding.severity,
            original_severity=str(finding.raw_data.get("rule", {}).get("level"))
            if isinstance(finding.raw_data.get("rule"), dict)
            else None,
            reasons=reasons,
            evidence=evidence,
            mitre_techniques=mitre_techniques,
            has_missing_data=has_missing_data,
            uncertainties=uncertainties,
            recommended_steps=recommended_steps,
            triaged_at=time.time(),
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _score_to_priority(
        self,
        score: int,
        sev_id: int,
        is_privileged: bool,
        has_high_impact_mitre: bool,
        has_public_ip: bool,
        context: InvestigationContext | None,
    ) -> IncidentPriority:
        """Map score to priority with defensive hard overrides."""
        # Hard Rule 1: Critical original severity with privileged user or high-impact attack must be CRITICAL
        if sev_id == 5 and (is_privileged or has_high_impact_mitre):
            return IncidentPriority.CRITICAL

        # Hard Rule 2: Informational alert with zero risk factors and no repetition cannot exceed LOW
        has_repetition = bool(context and context.historical_finding_count > 0)
        if sev_id == 1 and not (is_privileged or has_public_ip or has_high_impact_mitre or has_repetition):
            return IncidentPriority.LOW

        if score >= 80:
            return IncidentPriority.CRITICAL
        if score >= 60:
            return IncidentPriority.HIGH
        if score >= 35:
            return IncidentPriority.MEDIUM
        return IncidentPriority.LOW

    def _generate_recommendations(
        self,
        finding: OCSFSecurityFinding,
        priority: IncidentPriority,
        is_privileged: bool,
        has_public_ip: bool,
        has_high_impact_mitre: bool,
        resolution: ResolutionResult | None,
        context: InvestigationContext | None,
    ) -> list[str]:
        """Synthesize tailored, advisory investigation steps requiring human review."""
        steps: list[str] = []

        if is_privileged:
            user_name = finding.user.name if finding.user else "privileged account"
            steps.append(
                f"Inspect active sessions and recent authentication history for privileged user '{user_name}'."
            )
            steps.append(
                "Verify whether privileged operations were authorized under an active change ticket."
            )

        if has_high_impact_mitre:
            steps.append(
                "Examine process execution ancestry and command-line arguments on the affected host."
            )

        if has_public_ip:
            steps.append(
                "Query firewall and network flow logs for external communication to the indicator IP."
            )

        if resolution and resolution.conflicts:
            steps.append(
                "Review Wazuh agent enrollment and asset registration to reconcile entity identity conflict."
            )

        if context and not context.graph_available:
            steps.append(
                "Retry graph neighborhood lookup once Neo4j database connectivity is restored."
            )

        if priority in (IncidentPriority.HIGH, IncidentPriority.CRITICAL):
            steps.append(
                "Notify tier-2 SOC analyst for immediate manual triage and containment evaluation."
            )
        else:
            steps.append(
                "Archive finding in knowledge graph for ongoing baseline correlation."
            )

        return steps

    @staticmethod
    def _is_public_ip(ip_str: str) -> bool:
        """Return True if ip_str is a valid, globally routable public IP."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_global
        except ValueError:
            return False
