"""
normalization/models.py — Project-specific OCSF 1.1.0 Security Finding data models.

Defines a validated Pydantic model hierarchy implementing a project-specific
subset of the Open Cybersecurity Schema Framework (OCSF) v1.1.0 Security Finding
(Class UID: 2001, Category UID: 2: Findings).

DISCLAIMER:
This schema is a project-specific OCSF-style subset tailored specifically for
normalizing Wazuh security alerts in ThreatFusion AI. It is NOT claimed to be
an exhaustive or 100% strictly compliant implementation of the full OCSF
standard (which contains hundreds of optional attributes and profiles).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OCSFBaseModel(BaseModel):
    """Base Pydantic model for all OCSF schema entities."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
        validate_assignment=True,
    )


class OCSFProduct(OCSFBaseModel):
    """Product descriptor identifying the source security vendor/system."""

    name: str = "Wazuh"
    vendor_name: str = "Wazuh"
    version: str | None = None


class OCSFMetadata(OCSFBaseModel):
    """Metadata block for the OCSF event."""

    version: str = "1.1.0"
    schema_name: str = "project_ocsf_subset"
    product: OCSFProduct = Field(default_factory=OCSFProduct)
    original_time: str | None = None
    profiles: list[str] = Field(default_factory=lambda: ["security_control"])


class OCSFFindingInfo(OCSFBaseModel):
    """Core finding information characterizing the alert."""

    uid: str
    title: str
    desc: str | None = None
    types: list[str] = Field(default_factory=list)
    created_time: int | None = None
    src_url: str | None = None


class OCSFDevice(OCSFBaseModel):
    """Host or agent device associated with the event."""

    name: str | None = None
    uid: str | None = None
    ip: str | None = None
    type_id: int = 0  # 0: Unknown


class OCSFEndpoint(OCSFBaseModel):
    """Network endpoint descriptor for source or destination."""

    ip: str | None = None
    port: int | None = None
    protocol_name: str | None = None
    domain: str | None = None


class OCSFProcess(OCSFBaseModel):
    """Process context reported by the source (e.g. Windows eventdata)."""

    name: str | None = None
    cmd_line: str | None = None
    pid: int | None = None


class OCSFUser(OCSFBaseModel):
    """User account entity involved in the security event."""

    name: str
    uid: str | None = None


class OCSFTactic(OCSFBaseModel):
    """MITRE ATT&CK Tactic descriptor."""

    name: str


class OCSFTechnique(OCSFBaseModel):
    """MITRE ATT&CK Technique descriptor."""

    uid: str
    name: str | None = None


class OCSFAttack(OCSFBaseModel):
    """Adversary tactic and technique mapping (MITRE ATT&CK)."""

    tactic: OCSFTactic | None = None
    technique: OCSFTechnique | None = None


class OCSFSecurityFinding(OCSFBaseModel):
    """OCSF Security Finding (Class 2001) — Project-specific subset.

    Attributes conform to OCSF 1.1.0 Findings Category (Category 2, Class 2001).
    All untrusted alert contents are parsed safely, and raw alert data is preserved.
    """

    # OCSF Class and Category Identifiers
    class_uid: int = 2001
    class_name: str = "Security Finding"
    category_uid: int = 2
    category_name: str = "Findings"

    # Activity: 1 = Create
    activity_id: int = 1
    activity_name: str = "Create"

    # Severity mapping
    severity_id: int = Field(..., ge=0, le=6)
    severity: str

    # Status: 1 = New
    status_id: int = 1
    status: str = "New"

    # Event timestamp in epoch milliseconds
    time: int

    # Core object groupings
    metadata: OCSFMetadata
    finding_info: OCSFFindingInfo

    # Contextual entities (populated if present in raw alert)
    device: OCSFDevice | None = None
    src_endpoint: OCSFEndpoint | None = None
    dst_endpoint: OCSFEndpoint | None = None
    user: OCSFUser | None = None
    process: OCSFProcess | None = None
    attacks: list[OCSFAttack] = Field(default_factory=list)

    # Narrative message
    message: str | None = None

    # Original data preservation and unmapped / anomaly store
    raw_data: dict[str, Any]
    unmapped: dict[str, Any] = Field(default_factory=dict)
