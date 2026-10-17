"""
ingestion/enrichment.py — Unified threat intelligence and CMDB/IAM enrichment service.

Features:
- Enriches normalized OCSFSecurityFinding with MISP threat intelligence and CMDB asset context.
- Preserves the original finding unchanged; enrichment metadata is isolated.
- Respects the principle of explicit uncertainty: missing intel is UNKNOWN, not safe.
- Graceful degradation: handles disabled, offline, or failing providers honestly.
"""

from __future__ import annotations

import time
from typing import Any

from core.logger import get_logger
from ingestion.cmdb import (
    AssetContextRecord,
    IAMCMDBProvider,
    IdentityContextRecord,
    MockIAMCMDBProvider,
)
from ingestion.misp import MISPClient, MISPEnrichmentResult, MISPLookupStatus
from normalization.models import OCSFSecurityFinding

logger = get_logger("ingestion.enrichment")


class EnrichmentService:
    """Unified service querying external threat-intel (MISP) and asset context (CMDB/IAM)."""

    def __init__(
        self,
        misp_client: MISPClient | None = None,
        cmdb_provider: IAMCMDBProvider | None = None,
    ) -> None:
        self.misp_client = misp_client
        self.cmdb_provider = cmdb_provider or MockIAMCMDBProvider()

    async def enrich_finding(self, finding: OCSFSecurityFinding) -> dict[str, Any]:
        """Perform non-destructive enrichment on a normalized finding.

        Returns:
            dict[str, Any]: Structured enrichment payload containing MISP matches,
            asset context, identity context, and provenance metadata.
        """
        now = time.time()
        misp_results: list[MISPEnrichmentResult] = []

        # 1. Query MISP for observable network indicators (IPs, domains)
        if self.misp_client and self.misp_client.is_enabled:
            # Query source IP if present
            if finding.src_endpoint and finding.src_endpoint.ip:
                src_ip = finding.src_endpoint.ip.strip()
                res = await self.misp_client.lookup_indicator(src_ip, indicator_type="ip-dst")
                misp_results.append(res)

            # Query destination IP if present and different from source
            if finding.dst_endpoint and finding.dst_endpoint.ip:
                dst_ip = finding.dst_endpoint.ip.strip()
                if not finding.src_endpoint or dst_ip != finding.src_endpoint.ip:
                    res = await self.misp_client.lookup_indicator(dst_ip, indicator_type="ip-dst")
                    misp_results.append(res)
        elif self.misp_client:
            # Client present but disabled/unconfigured
            if finding.src_endpoint and finding.src_endpoint.ip:
                misp_results.append(
                    MISPEnrichmentResult(
                        indicator=finding.src_endpoint.ip,
                        status=MISPLookupStatus.DISABLED,
                        retrieved_at=now,
                        error_message="MISP integration is not configured or disabled",
                    )
                )

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

        asset_dict = asset_record.model_dump() if asset_record else None
        identity_dict = identity_record.model_dump() if identity_record else None
        misp_list = [r.model_dump() for r in misp_results]
        misp_map = {r.indicator: r.model_dump() for r in misp_results}

        return {
            "finding_id": finding.finding_info.uid,
            "misp": misp_list,
            "misp_indicators": misp_map,
            "asset": asset_dict,
            "cmdb_asset": asset_dict,
            "identity": identity_dict,
            "iam_identity": identity_dict,
            "enriched_at": now,
        }
