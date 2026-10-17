"""
normalization — OCSF 1.1.0 alert normalization for ThreatFusion AI.

Converts raw, untrusted Wazuh alerts into validated, typed OCSFSecurityFinding
models (project-specific OCSF 1.1.0 subset).
"""

from normalization.models import (
    OCSFAttack,
    OCSFBaseModel,
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
from normalization.normalizer import (
    AlertSchemaError,
    NormalizationError,
    OCSFNormalizer,
)

__all__ = [
    "AlertSchemaError",
    "NormalizationError",
    "OCSFAttack",
    "OCSFBaseModel",
    "OCSFDevice",
    "OCSFEndpoint",
    "OCSFFindingInfo",
    "OCSFMetadata",
    "OCSFNormalizer",
    "OCSFProduct",
    "OCSFSecurityFinding",
    "OCSFTactic",
    "OCSFTechnique",
    "OCSFUser",
]
