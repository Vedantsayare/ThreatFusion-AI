"""
ingestion/cmdb.py — Provider-neutral IAM and CMDB asset/identity context provider.

Features:
- Provider-neutral typed models for Asset and Identity records.
- Preserves provenance and distinguishing confirmed absence from missing lookup.
- Never invents missing attributes (ownership, criticality, or identities).
- Provider-neutral interface (IAMCMDBProvider) and MockIAMCMDBProvider for testing.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AssetCriticality(str, Enum):
    """Business criticality of a monitored asset."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class AccountStatus(str, Enum):
    """Lifecycle status of a user identity account."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    LOCKED = "LOCKED"
    DELETED = "DELETED"
    UNKNOWN = "UNKNOWN"


class AssetContextRecord(BaseModel):
    """CMDB asset context record."""

    model_config = ConfigDict(extra="ignore")

    asset_id: str
    hostname: str | None = None
    ip_address: str | None = None
    owner_team: str | None = None
    environment: str | None = None  # e.g. "production", "staging", "development"
    criticality: AssetCriticality = AssetCriticality.UNKNOWN
    tags: list[str] = Field(default_factory=list)
    source: str = "cmdb"
    retrieved_at: float = Field(default_factory=time.time)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class IdentityContextRecord(BaseModel):
    """IAM identity context record."""

    model_config = ConfigDict(extra="ignore")

    username: str
    full_name: str | None = None
    email: str | None = None
    department: str | None = None
    status: AccountStatus = AccountStatus.UNKNOWN
    is_privileged: bool = False
    source: str = "iam"
    retrieved_at: float = Field(default_factory=time.time)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class IAMCMDBProvider(ABC):
    """Abstract interface for querying asset and identity context."""

    @abstractmethod
    async def get_asset_context(
        self,
        asset_id: str | None = None,
        hostname: str | None = None,
        ip: str | None = None,
    ) -> AssetContextRecord | None:
        """Retrieve asset context by ID, hostname, or IP. Returns None if unknown."""

    @abstractmethod
    async def get_identity_context(self, username: str) -> IdentityContextRecord | None:
        """Retrieve identity context by username. Returns None if unknown."""


class MockIAMCMDBProvider(IAMCMDBProvider):
    """In-memory mock CMDB and IAM provider with deterministic seed records."""

    def __init__(
        self,
        assets: list[AssetContextRecord] | None = None,
        identities: list[IdentityContextRecord] | None = None,
    ) -> None:
        self._assets_by_id: dict[str, AssetContextRecord] = {}
        self._assets_by_host: dict[str, AssetContextRecord] = {}
        self._assets_by_ip: dict[str, AssetContextRecord] = {}
        self._identities: dict[str, IdentityContextRecord] = {}

        # Default sample inventory
        default_assets = assets or [
            AssetContextRecord(
                asset_id="001",
                hostname="web-server-01",
                ip_address="192.168.1.50",
                owner_team="Platform Security",
                environment="production",
                criticality=AssetCriticality.HIGH,
                tags=["pci-dss", "dmz"],
                source="mock_cmdb",
            ),
            AssetContextRecord(
                asset_id="002",
                hostname="db-server-01",
                ip_address="192.168.1.51",
                owner_team="Data Services",
                environment="production",
                criticality=AssetCriticality.CRITICAL,
                tags=["database", "customer-pii"],
                source="mock_cmdb",
            ),
        ]

        default_identities = identities or [
            IdentityContextRecord(
                username="root",
                full_name="Superuser Account",
                department="Infrastructure Operations",
                status=AccountStatus.ACTIVE,
                is_privileged=True,
                source="mock_iam",
            ),
            IdentityContextRecord(
                username="admin",
                full_name="Default Administrator",
                department="IT Administration",
                status=AccountStatus.ACTIVE,
                is_privileged=True,
                source="mock_iam",
            ),
            IdentityContextRecord(
                username="analyst_alice",
                full_name="Alice Tier2",
                email="alice@company.local",
                department="Security Operations Center",
                status=AccountStatus.ACTIVE,
                is_privileged=False,
                source="mock_iam",
            ),
        ]

        for asset in default_assets:
            self.add_asset(asset)

        for identity in default_identities:
            self.add_identity(identity)

    def add_asset(self, asset: AssetContextRecord) -> None:
        """Register an asset record."""
        if asset.asset_id:
            self._assets_by_id[asset.asset_id.lower()] = asset
        if asset.hostname:
            self._assets_by_host[asset.hostname.lower()] = asset
        if asset.ip_address:
            self._assets_by_ip[asset.ip_address.lower()] = asset

    def add_identity(self, identity: IdentityContextRecord) -> None:
        """Register an identity record."""
        self._identities[identity.username.lower()] = identity

    async def get_asset_context(
        self,
        asset_id: str | None = None,
        hostname: str | None = None,
        ip: str | None = None,
    ) -> AssetContextRecord | None:
        """Look up asset context; does not invent missing data."""
        if asset_id and asset_id.lower() in self._assets_by_id:
            return self._assets_by_id[asset_id.lower()]
        if hostname and hostname.lower() in self._assets_by_host:
            return self._assets_by_host[hostname.lower()]
        if ip and ip.lower() in self._assets_by_ip:
            return self._assets_by_ip[ip.lower()]
        return None

    async def get_identity_context(self, username: str) -> IdentityContextRecord | None:
        """Look up identity context; returns None for unknown users."""
        clean = username.strip().lower()
        return self._identities.get(clean)
