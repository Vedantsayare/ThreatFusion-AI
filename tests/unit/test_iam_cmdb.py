"""
tests/unit/test_iam_cmdb.py — Unit tests for IAM/CMDB asset and identity provider.
"""

from __future__ import annotations

import pytest

from ingestion.cmdb import (
    AccountStatus,
    AssetContextRecord,
    AssetCriticality,
    IAMCMDBProvider,
    IdentityContextRecord,
    MockIAMCMDBProvider,
)


@pytest.fixture
def mock_provider() -> MockIAMCMDBProvider:
    """Instantiate MockIAMCMDBProvider with default seed data."""
    return MockIAMCMDBProvider()


@pytest.mark.asyncio
async def test_cmdb_lookup_known_asset(mock_provider: MockIAMCMDBProvider) -> None:
    """Verify lookup of seeded high-value database server."""
    asset = await mock_provider.get_asset_context(hostname="db-server-01")
    assert asset is not None
    assert asset.hostname == "db-server-01"
    assert asset.criticality == AssetCriticality.CRITICAL
    assert asset.environment == "production"
    assert asset.ip_address == "192.168.1.51"
    assert asset.owner_team == "Data Services"


@pytest.mark.asyncio
async def test_cmdb_lookup_by_ip(mock_provider: MockIAMCMDBProvider) -> None:
    """Verify lookup by IP address."""
    asset = await mock_provider.get_asset_context(ip="192.168.1.50")
    assert asset is not None
    assert asset.hostname == "web-server-01"
    assert asset.criticality == AssetCriticality.HIGH


@pytest.mark.asyncio
async def test_cmdb_lookup_unknown_asset(mock_provider: MockIAMCMDBProvider) -> None:
    """Verify unknown host returns None without fabricating attributes."""
    asset = await mock_provider.get_asset_context(hostname="non-existent-host-99")
    assert asset is None


@pytest.mark.asyncio
async def test_iam_lookup_known_identity(mock_provider: MockIAMCMDBProvider) -> None:
    """Verify lookup of privileged administrator."""
    identity = await mock_provider.get_identity_context(username="admin")
    assert identity is not None
    assert identity.username == "admin"
    assert identity.is_privileged is True
    assert identity.status == AccountStatus.ACTIVE


@pytest.mark.asyncio
async def test_iam_lookup_unknown_identity(mock_provider: MockIAMCMDBProvider) -> None:
    """Verify unknown user returns None without fabricating attributes."""
    identity = await mock_provider.get_identity_context(username="phantom_user")
    assert identity is None


@pytest.mark.asyncio
async def test_custom_cmdb_provider_contract() -> None:
    """Verify custom provider implementing the IAMCMDBProvider abstract base class."""
    class CustomProvider(IAMCMDBProvider):
        async def get_asset_context(
            self,
            asset_id: str | None = None,
            hostname: str | None = None,
            ip: str | None = None,
        ) -> AssetContextRecord | None:
            return AssetContextRecord(
                asset_id="custom-1",
                hostname=hostname or "custom-host",
                criticality=AssetCriticality.MEDIUM,
                environment="staging",
            )

        async def get_identity_context(self, username: str) -> IdentityContextRecord | None:
            return IdentityContextRecord(
                username=username,
                is_privileged=False,
                status=AccountStatus.ACTIVE,
            )

    provider = CustomProvider()
    asset = await provider.get_asset_context(hostname="staging-web")
    identity = await provider.get_identity_context(username="analyst_jane")

    assert asset is not None
    assert asset.criticality == AssetCriticality.MEDIUM
    assert identity is not None
    assert identity.is_privileged is False
