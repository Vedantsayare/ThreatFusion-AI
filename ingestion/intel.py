"""
ingestion/intel.py — Indicator verdicts and the synthetic demo threat-intel feed.

Verdict vocabulary (strongest first):
- MALICIOUS  — a source explicitly reports the indicator as malicious.
- SUSPICIOUS — a source reports it with low/undefined threat level.
- BENIGN     — a source explicitly lists it as known-good AND no source disagrees.
- UNKNOWN    — no source has information, or every lookup failed/was disabled.

Absence of intelligence is UNKNOWN, never BENIGN. Lookup failures are reported
as "unavailable" so analysts can tell "nobody knows" from "we could not ask".

The demo feed contains ONLY documentation-reserved addresses (RFC 5737:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Every verdict it produces is
labelled ``source="demo_intel_feed"`` and ``synthetic=True``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ingestion.misp import MISPEnrichmentResult, MISPLookupStatus


class IntelVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


_STRENGTH = {
    IntelVerdict.MALICIOUS: 3,
    IntelVerdict.SUSPICIOUS: 2,
    IntelVerdict.BENIGN: 1,
    IntelVerdict.UNKNOWN: 0,
}


class SourceVerdict(BaseModel):
    """One source's opinion about an indicator."""

    model_config = ConfigDict(extra="ignore")

    source: str
    verdict: IntelVerdict
    detail: str
    available: bool = True
    synthetic: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    references: list[str] = Field(default_factory=list)


class IndicatorAssessment(BaseModel):
    """Combined verdict for one indicator across all sources."""

    model_config = ConfigDict(extra="ignore")

    indicator: str
    indicator_type: str
    verdict: IntelVerdict
    rationale: str
    sources: list[SourceVerdict] = Field(default_factory=list)
    conflicting: bool = False
    synthetic: bool = False
    # Kept for compatibility with the MISP safety contract.
    is_confirmed_safe: bool = False


def combine_verdicts(indicator: str, indicator_type: str, sources: list[SourceVerdict]) -> IndicatorAssessment:
    """Combine per-source verdicts: strongest negative signal wins.

    BENIGN survives only if no available source reports MALICIOUS/SUSPICIOUS.
    """
    informative = [s for s in sources if s.available and s.verdict != IntelVerdict.UNKNOWN]
    if not informative:
        unavailable = [f"{s.source}: {s.detail}" for s in sources if not s.available]
        why = (
            f"No intelligence available ({'; '.join(unavailable)})"
            if unavailable
            else "No source has information about this indicator"
        )
        return IndicatorAssessment(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=IntelVerdict.UNKNOWN,
            rationale=f"{why}. Absence of intelligence is not evidence of safety.",
            sources=sources,
        )

    strongest = max(informative, key=lambda s: _STRENGTH[s.verdict])
    distinct = {s.verdict for s in informative}
    conflicting = IntelVerdict.BENIGN in distinct and len(distinct) > 1
    rationale = f"{strongest.source}: {strongest.detail}"
    if conflicting:
        rationale += " (sources disagree; the most severe verdict is used)"

    return IndicatorAssessment(
        indicator=indicator,
        indicator_type=indicator_type,
        verdict=strongest.verdict,
        rationale=rationale,
        sources=sources,
        conflicting=conflicting,
        synthetic=all(s.synthetic for s in informative),
        is_confirmed_safe=False,
    )


def misp_to_source_verdict(result: MISPEnrichmentResult) -> SourceVerdict:
    """Translate a MISP lookup into a source verdict.

    MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined.
    """
    if result.status == MISPLookupStatus.MATCH_FOUND:
        levels = [m.threat_level_id for m in result.matches if m.threat_level_id is not None]
        high = any(int(level) == 1 for level in levels)
        events = [f"MISP event {m.event_id}: {m.event_info}" for m in result.matches[:3]]
        return SourceVerdict(
            source="misp",
            verdict=IntelVerdict.MALICIOUS if high else IntelVerdict.SUSPICIOUS,
            detail=f"{result.match_count} MISP attribute match(es)"
            + (" with high threat level" if high else " with medium/low/undefined threat level"),
            confidence=result.confidence,
            references=events,
        )
    if result.status == MISPLookupStatus.NO_MATCH:
        return SourceVerdict(source="misp", verdict=IntelVerdict.UNKNOWN, detail="No MISP match")
    if result.status == MISPLookupStatus.DISABLED:
        detail = "not configured"
    else:
        detail = f"lookup {result.status.value.lower()}: {result.error_message or 'no detail'}"
    return SourceVerdict(source="misp", verdict=IntelVerdict.UNKNOWN, detail=detail, available=False)


# ── Synthetic demo feed ─────────────────────────────────────────────────────

_DEMO_FEED: dict[str, tuple[IntelVerdict, str]] = {
    "198.51.100.22": (IntelVerdict.MALICIOUS, "Synthetic C2 server listed in demo feed"),
    "198.51.100.88": (IntelVerdict.SUSPICIOUS, "Synthetic SSH scanning source listed in demo feed"),
    "203.0.113.50": (IntelVerdict.MALICIOUS, "Synthetic exfiltration drop host listed in demo feed"),
    "203.0.113.195": (IntelVerdict.SUSPICIOUS, "Synthetic brute-force source listed in demo feed"),
    "192.0.2.10": (IntelVerdict.BENIGN, "Synthetic allow-listed package mirror in demo feed"),
    "updates.example.com": (IntelVerdict.BENIGN, "Synthetic allow-listed update domain in demo feed"),
    "files.example.net": (IntelVerdict.MALICIOUS, "Synthetic file-sharing exfil domain in demo feed"),
}


class DemoIntelFeed:
    """Static synthetic indicator list for offline demonstrations."""

    name = "demo_intel_feed"

    def lookup(self, indicator: str) -> SourceVerdict:
        entry = _DEMO_FEED.get(indicator.strip().lower())
        if entry is None:
            return SourceVerdict(
                source=self.name,
                verdict=IntelVerdict.UNKNOWN,
                detail="Not present in synthetic demo feed",
                synthetic=True,
            )
        verdict, detail = entry
        return SourceVerdict(
            source=self.name,
            verdict=verdict,
            detail=detail,
            synthetic=True,
            confidence=0.9,
            references=["synthetic: demo feed entry (RFC 5737 documentation range)"],
        )

    @staticmethod
    def entries() -> list[dict[str, Any]]:
        return [
            {"indicator": k, "verdict": v.value, "detail": d, "synthetic": True}
            for k, (v, d) in sorted(_DEMO_FEED.items())
        ]
