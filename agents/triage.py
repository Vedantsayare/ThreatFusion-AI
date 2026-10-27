"""
agents/triage.py — Deterministic, rule-and-score-based alert triage engine.

Evaluates normalized OCSF findings, Phase 4 resolution evidence, and Phase 5
graph context to assign deterministic incident priorities (LOW, MEDIUM, HIGH, CRITICAL).
Treats missing data as unknown rather than safe and never calls external LLMs.
"""

from __future__ import annotations

import re
import time
from typing import Any

from agents.models import (
    EvidenceItem,
    IncidentPriority,
    InvestigationContext,
    ScoreContribution,
    TriageResult,
)
from core.logger import get_logger
from graph.models import ResolutionResult
from normalization.models import OCSFSecurityFinding
from normalization.net import is_external_ip

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


# Environmental context (not the detected behaviour itself); see the CRITICAL rule
# in AlertTriageEngine._score_to_priority_with_rule.
CONTEXT_FACTORS = frozenset({"threat_intel", "asset_criticality"})


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
        malicious_intel_boost: int = 20,
        suspicious_intel_boost: int = 10,
        asset_criticality_boosts: dict[str, int] | None = None,
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
        self.malicious_intel_boost = malicious_intel_boost
        self.suspicious_intel_boost = suspicious_intel_boost
        self.asset_criticality_boosts = asset_criticality_boosts or {"CRITICAL": 10, "HIGH": 5}


class AlertTriageEngine:
    """Deterministic triage engine mapping findings and context to incident priorities."""

    def __init__(self, policy: TriagePolicy | None = None) -> None:
        self.policy = policy or TriagePolicy()

    def triage(
        self,
        finding: OCSFSecurityFinding,
        resolution: ResolutionResult | None = None,
        context: InvestigationContext | None = None,
        enrichment: dict[str, Any] | None = None,
    ) -> TriageResult:
        """Evaluate a normalized security finding and compute its deterministic triage priority.

        Args:
            finding: Normalized OCSF security finding.
            resolution: Optional Phase 4 resolution result.
            context: Optional Phase 5 investigation context from Neo4j.
            enrichment: Optional threat-intel verdicts and CMDB/IAM context.

        Returns:
            TriageResult: Strongly typed priority, score, reasons, evidence, and recommendations.
        """
        finding_id = finding.finding_info.uid
        reasons: list[str] = []
        evidence: list[EvidenceItem] = []
        mitre_techniques: list[str] = []
        uncertainties: list[str] = []
        breakdown: list[ScoreContribution] = []
        has_missing_data = False

        # 1. Base Score from OCSF Severity
        sev_id = finding.severity_id
        base_score = self.policy.base_severity_scores.get(sev_id, 25)
        score = base_score
        breakdown.append(
            ScoreContribution(
                factor="base_severity",
                points=base_score,
                detail=f"OCSF severity {finding.severity} (level {sev_id})",
                evidence_ref=f"finding:{finding_id}",
            )
        )

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

        # 2. Privileged Account Factor (name list OR IAM flag — counted once)
        is_privileged = False
        iam_identity = (enrichment or {}).get("iam_identity") or {}
        if finding.user is not None and finding.user.name:
            username_clean = finding.user.name.strip().lower()
            # Match exact account name or first token delimited by punctuation/whitespace
            first_token = re.split(r"['\"\s:@\\]+", username_clean)[0]
            iam_privileged = bool(iam_identity.get("is_privileged"))
            if username_clean in PRIVILEGED_ACCOUNTS or first_token in PRIVILEGED_ACCOUNTS or iam_privileged:
                is_privileged = True
                breakdown.append(
                    ScoreContribution(
                        factor="privileged_account",
                        points=self.policy.privileged_account_boost,
                        detail=f"Account '{finding.user.name}' is privileged"
                        + (" (IAM record)" if iam_privileged else " (privileged account name)"),
                        evidence_ref=f"identity:{finding.user.name}",
                    )
                )
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
                    breakdown.append(
                        ScoreContribution(
                            factor="external_exposure",
                            points=self.policy.public_ip_boost,
                            detail=f"Globally routable IP in {role} role ({ip_clean})",
                            evidence_ref=f"ioc:ip:{ip_clean}",
                        )
                    )
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
                    breakdown.append(
                        ScoreContribution(
                            factor="high_impact_technique",
                            points=self.policy.high_impact_mitre_boost,
                            detail=f"Alert maps to high-impact ATT&CK technique {t_id}"
                            + (f" ({tactic_name})" if tactic_name else ""),
                            evidence_ref=f"ttp:{t_id}",
                        )
                    )
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
                breakdown.append(
                    ScoreContribution(
                        factor="historical_recurrence",
                        points=boost,
                        detail=f"{hist_count} prior finding(s) on this asset in graph memory",
                        evidence_ref="neo4j_graph",
                    )
                )
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

        # 6b. Threat intelligence (strongest verdict, applied once per finding)
        verdicts = (enrichment or {}).get("indicator_verdicts") or {}
        intel_factor: tuple[str, str] | None = None  # (verdict, indicator)
        subsumed_exposure = 0  # exposure points folded into the intel factor (still intrinsic)
        for indicator, record in verdicts.items():
            verdict = str(record.get("verdict", "UNKNOWN"))
            if verdict == "MALICIOUS":
                intel_factor = (verdict, indicator)
                break
            if verdict == "SUSPICIOUS" and intel_factor is None:
                intel_factor = (verdict, indicator)
        if intel_factor is not None:
            verdict, indicator = intel_factor
            record = verdicts[indicator]
            points = (
                self.policy.malicious_intel_boost if verdict == "MALICIOUS" else self.policy.suspicious_intel_boost
            )
            synthetic = " [synthetic demo intel]" if record.get("synthetic") else ""
            # Same-indicator evidence is counted once: reputation for an IP already
            # implies it is external, so intel on that IP subsumes its exposure points.
            exposure = next(
                (c for c in breakdown if c.factor == "external_exposure" and c.evidence_ref == f"ioc:ip:{indicator}"),
                None,
            )
            if exposure is not None:
                breakdown.remove(exposure)
                score -= exposure.points
                subsumed_exposure = exposure.points
                reasons[:] = [r for r in reasons if f"({indicator})" not in r or "External/public IP" not in r]
                synthetic += f" (subsumes +{exposure.points} external exposure of the same IP)"
            score += points
            breakdown.append(
                ScoreContribution(
                    factor="threat_intel",
                    points=points,
                    detail=f"{indicator} assessed {verdict}: {record.get('rationale', '')}{synthetic}",
                    evidence_ref=f"intel:{indicator}",
                )
            )
            reasons.append(f"Threat intelligence marks {indicator} as {verdict}{synthetic} (+{points})")
            evidence.append(
                EvidenceItem(
                    source="threat_intel",
                    evidence_type="indicator_reputation",
                    detail=f"{indicator}: {verdict}",
                    confidence=0.9 if verdict == "MALICIOUS" else 0.6,
                    data={"indicator": indicator, "verdict": verdict, "synthetic": bool(record.get("synthetic"))},
                )
            )
        unknown = [i for i, r in verdicts.items() if r.get("verdict") == "UNKNOWN"]
        if unknown:
            uncertainties.append(
                f"No threat intelligence for {', '.join(unknown)} (unknown, not assumed benign)"
            )

        # 6c. Asset criticality from CMDB (only when the CMDB has a record)
        asset = (enrichment or {}).get("cmdb_asset") or {}
        criticality = str(asset.get("criticality", "")).upper()
        crit_points = self.policy.asset_criticality_boosts.get(criticality, 0)
        if crit_points:
            score += crit_points
            breakdown.append(
                ScoreContribution(
                    factor="asset_criticality",
                    points=crit_points,
                    detail=f"CMDB criticality {criticality} for {asset.get('hostname') or asset.get('asset_id')}",
                    evidence_ref=f"cmdb:{asset.get('asset_id')}",
                )
            )
            reasons.append(f"Asset criticality {criticality} per CMDB (+{crit_points})")
        elif enrichment is not None and finding.device is not None and not asset:
            uncertainties.append("Asset not found in CMDB; criticality unknown")

        # 7. Check Missing Attributes in Telemetry
        if finding.device is None:
            has_missing_data = True
            uncertainties.append("Alert lacks host/device attribution")
        if finding.metadata.original_time is None or finding.unmapped.get("timestamp_warning"):
            has_missing_data = True
            uncertainties.append("Event timestamp missing or defaulted from system clock")

        # 8. Bounded Score Calculation & Priority Assignment
        raw_score = score
        score = max(0, min(100, score))
        if raw_score != score:
            breakdown.append(
                ScoreContribution(factor="clamp", points=score - raw_score, detail="Score clamped to 0-100 range")
            )
        context_points = sum(c.points for c in breakdown if c.factor in CONTEXT_FACTORS)
        priority, priority_rule = self._score_to_priority_with_rule(
            score=score,
            sev_id=sev_id,
            is_privileged=is_privileged,
            has_high_impact_mitre=has_high_impact_mitre,
            has_public_ip=has_public_ip,
            context=context,
            # Exposure folded into the intel factor is an observed fact, so it stays intrinsic.
            intrinsic_score=max(0, min(100, raw_score - context_points + subsumed_exposure)),
            malicious_intel=intel_factor is not None and intel_factor[0] == "MALICIOUS",
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
            score_breakdown=breakdown,
            priority_rule=priority_rule,
            evidence=evidence,
            mitre_techniques=mitre_techniques,
            has_missing_data=has_missing_data,
            uncertainties=uncertainties,
            recommended_steps=recommended_steps,
            triaged_at=time.time(),
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _score_to_priority_with_rule(
        self,
        score: int,
        sev_id: int,
        is_privileged: bool,
        has_high_impact_mitre: bool,
        has_public_ip: bool,
        context: InvestigationContext | None,
        intrinsic_score: int | None = None,
        malicious_intel: bool = False,
    ) -> tuple[IncidentPriority, str]:
        """Return the priority plus a human-readable statement of the rule applied.

        Context factors (asset criticality, SUSPICIOUS intel) describe the
        environment, not the detected behaviour. They may raise priority up to
        HIGH but cannot by themselves make an alert CRITICAL: CRITICAL needs an
        intrinsic score >= 80, a hard rule, or a MALICIOUS intel verdict.
        """
        priority = self._score_to_priority(
            score=score,
            sev_id=sev_id,
            is_privileged=is_privileged,
            has_high_impact_mitre=has_high_impact_mitre,
            has_public_ip=has_public_ip,
            context=context,
        )
        if sev_id == 5 and (is_privileged or has_high_impact_mitre):
            return priority, "Hard rule: critical source severity with privileged account or high-impact technique => CRITICAL"
        if priority == IncidentPriority.LOW and sev_id == 1:
            return priority, "Hard rule: informational alert with no risk factors => LOW"
        intrinsic = score if intrinsic_score is None else intrinsic_score
        if priority == IncidentPriority.CRITICAL and intrinsic < 80 and not malicious_intel:
            return (
                IncidentPriority.HIGH,
                f"Score {score} (intrinsic {intrinsic}): context factors alone cannot raise an alert to CRITICAL => HIGH",
            )
        return priority, f"Score {score}: >=80 CRITICAL, >=60 HIGH, >=35 MEDIUM, else LOW"

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
        """Return True if ip_str is external (see normalization.net.is_external_ip)."""
        return is_external_ip(ip_str)
