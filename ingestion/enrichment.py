"""
ingestion/enrichment.py — Unified threat intelligence and CMDB/IAM enrichment service.

Features:
- Enriches normalized OCSFSecurityFinding with MISP threat intelligence and CMDB asset context.
- Preserves the original finding unchanged; enrichment metadata is isolated.
- Respects the principle of explicit uncertainty: missing intel is UNKNOWN, not safe.
- Graceful degradation: handles disabled, offline, or failing providers honestly.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from core.logger import get_logger
from ingestion.cmdb import (
    AssetContextRecord,
    IAMCMDBProvider,
    IdentityContextRecord,
    MockIAMCMDBProvider,
)
from ingestion.intel import (
    DemoIntelFeed,
    IndicatorAssessment,
    SourceVerdict,
    combine_verdicts,
    misp_to_source_verdict,
)
from ingestion.misp import MISPClient, MISPEnrichmentResult, MISPLookupStatus
from normalization.models import OCSFSecurityFinding
from normalization.net import is_external_ip

logger = get_logger("ingestion.enrichment")


class EnrichmentService:
    """Unified service querying external threat-intel (MISP) and asset context (CMDB/IAM)."""

    def __init__(
        self,
        misp_client: MISPClient | None = None,
        cmdb_provider: IAMCMDBProvider | None = None,
        demo_feed: DemoIntelFeed | None = None,
        misp_budget_seconds: float = 8.0,
    ) -> None:
        self.misp_client = misp_client
        self.cmdb_provider = cmdb_provider or MockIAMCMDBProvider()
        # Optional synthetic feed (demo mode only); its verdicts are labelled synthetic.
        self.demo_feed = demo_feed
        # Wall-clock cap per MISP lookup (covers the client's own retries) so a slow
        # MISP degrades to "unavailable" without discarding other enrichment.
        self.misp_budget_seconds = misp_budget_seconds

    @staticmethod
    def observed_indicators(finding: OCSFSecurityFinding) -> list[tuple[str, str, str]]:
        """Return (indicator, type, role) for external IPs and domains present in the finding."""
        seen: set[str] = set()
        out: list[tuple[str, str, str]] = []
        for endpoint, role in ((finding.src_endpoint, "source"), (finding.dst_endpoint, "destination")):
            if endpoint is None:
                continue
            # Only external IPs are looked up: private addresses carry no intel
            # value and would disclose internal addressing to the intel source.
            if endpoint.ip and endpoint.ip.strip() not in seen and is_external_ip(endpoint.ip):
                seen.add(endpoint.ip.strip())
                out.append((endpoint.ip.strip(), "ip", role))
            if endpoint.domain and endpoint.domain.strip().lower() not in seen:
                seen.add(endpoint.domain.strip().lower())
                out.append((endpoint.domain.strip().lower(), "domain", role))
        return out

    async def lookup_indicator(self, indicator: str, indicator_type: str) -> tuple[IndicatorAssessment, MISPEnrichmentResult | None]:
        """Assess one indicator across all configured sources."""
        sources: list[SourceVerdict] = []
        misp_result: MISPEnrichmentResult | None = None

        if self.misp_client and self.misp_client.is_enabled:
            misp_type = "ip-dst" if indicator_type == "ip" else "domain"
            try:
                misp_result = await asyncio.wait_for(
                    self.misp_client.lookup_indicator(indicator, indicator_type=misp_type),
                    timeout=self.misp_budget_seconds,
                )
            except Exception as err:
                misp_result = MISPEnrichmentResult(
                    indicator=indicator,
                    status=MISPLookupStatus.SERVICE_UNAVAILABLE,
                    retrieved_at=time.time(),
                    error_message=f"{type(err).__name__} after {self.misp_budget_seconds:.0f}s budget",
                )
            sources.append(misp_to_source_verdict(misp_result))
        elif self.misp_client:
            misp_result = MISPEnrichmentResult(
                indicator=indicator,
                status=MISPLookupStatus.DISABLED,
                retrieved_at=time.time(),
                error_message="MISP integration is not configured or disabled",
            )
            sources.append(misp_to_source_verdict(misp_result))

        if self.demo_feed is not None:
            sources.append(self.demo_feed.lookup(indicator))

        return combine_verdicts(indicator, indicator_type, sources), misp_result

    async def enrich_finding(self, finding: OCSFSecurityFinding) -> dict[str, Any]:
        """Perform non-destructive enrichment on a normalized finding.

        Returns:
            dict[str, Any]: Structured enrichment payload containing MISP matches,
            per-indicator verdicts, asset context, identity context, and provenance.
        """
        now = time.time()
        misp_results: list[MISPEnrichmentResult] = []
        verdicts: dict[str, dict[str, Any]] = {}

        # 1. Threat intel for every observed network indicator (IPs, domains)
        for indicator, indicator_type, role in self.observed_indicators(finding):
            assessment, misp_result = await self.lookup_indicator(indicator, indicator_type)
            if misp_result is not None:
                misp_results.append(misp_result)
            record = assessment.model_dump(mode="json")
            record["role"] = role
            verdicts[indicator] = record

        # 2. Query CMDB for asset context
        asset_record: AssetContextRecord | None = None
        if self.cmdb_provider and finding.device:
            asset_record = await self.cmdb_provider.get_asset_context(
                asset_id=finding.device.uid if finding.device.uid != "000" else None,
                hostname=finding.device.name,
                ip=finding.device.ip,
            )

        # 3. Query IAM for identity context
        identity_record: IdentityContextRecord | None = None
        if self.cmdb_provider and finding.user and finding.user.name:
            identity_record = await self.cmdb_provider.get_identity_context(
                username=finding.user.name,
            )

        asset_dict = asset_record.model_dump(mode="json") if asset_record else None
        identity_dict = identity_record.model_dump(mode="json") if identity_record else None
        misp_list = [r.model_dump(mode="json") for r in misp_results]
        misp_map = {r.indicator: r.model_dump(mode="json") for r in misp_results}

        return {
            "finding_id": finding.finding_info.uid,
            "misp": misp_list,
            "misp_indicators": misp_map,
            "indicator_verdicts": verdicts,
            "asset": asset_dict,
            "cmdb_asset": asset_dict,
            "identity": identity_dict,
            "iam_identity": identity_dict,
            "sources": {
                "misp": "enabled" if (self.misp_client and self.misp_client.is_enabled) else "not_configured",
                "demo_intel_feed": "enabled (synthetic)" if self.demo_feed else "disabled",
                "cmdb": type(self.cmdb_provider).__name__ if self.cmdb_provider else "none",
            },
            "enriched_at": now,
        }
