"""
Data model shared by every module in the risk engine.

`Finding` mirrors (a subset of) what the ECDAT scanner already emits per
detected artefact. Everything else in this package reads from a `Finding`
and produces a `RiskScore` and/or a `Recommendation` for it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Layer(str, Enum):
    """Where the cryptography is doing its job (Section 5 of the design doc)."""
    IN_TRANSIT = "in_transit"
    IN_USE = "in_use"
    AT_REST = "at_rest"


class Purpose(str, Enum):
    """What the cryptographic primitive is actually for."""
    KEY_EXCHANGE = "key_exchange"       # KEM / key agreement
    ENCRYPTION = "encryption"           # bulk symmetric encryption
    SIGNING = "signing"                 # digital signatures / authentication
    INTEGRITY = "integrity"             # MAC / integrity tag only
    UNKNOWN = "unknown"


class Sensitivity(str, Enum):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


class DeviceClass(str, Enum):
    CONSTRAINED = "constrained"   # IoT / embedded / SCADA-adjacent
    STANDARD = "standard"         # typical server / VM
    CLOUD = "cloud"               # elastic cloud-native service


class RiskBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """
    One cryptographic artefact as reported by ECDAT, plus the small amount
    of extra context (sensitivity, exposure, device class, time estimates)
    the risk engine needs that the scanner itself cannot see from code alone.

    Only `finding_id`, `finding_type`, `algorithm` and `location` are
    required to come from the scanner. Everything else has a safe default
    so the engine can run even before those enrichment sources exist.
    """

    finding_id: str
    finding_type: str          # e.g. "certificate", "tls_config", "code_call", "container_secret"
    algorithm: str             # e.g. "RSA", "ECC", "AES", "ML-KEM", "DH", "ChaCha20"
    location: str
    key_size: Optional[int] = None
    confidence: float = 1.0    # ECDAT's own detection confidence, kept separate from risk

    # --- context the scanner can partially infer, or that comes from policy/user tags ---
    purpose: Purpose = Purpose.UNKNOWN
    tag_length_bits: Optional[int] = None       # for MAC/integrity findings
    key_is_long_lived: Optional[bool] = None    # e.g. from cert validity period
    sensitivity: Sensitivity = Sensitivity.MODERATE
    device_class: DeviceClass = DeviceClass.STANDARD
    internet_facing: bool = False
    public_registry: bool = False
    third_party_api: bool = False

    # --- timeline inputs (years); sensible defaults, meant to be overridden per finding ---
    data_lifetime_years: Optional[float] = None      # X
    migration_effort_years: Optional[float] = None   # Y

    # free-form extra data the caller wants carried through untouched
    extra: dict = field(default_factory=dict)


@dataclass
class RiskScore:
    """Output of the scoring engine (Sections 5-6 of the design doc) for one finding."""

    finding_id: str
    layer: Layer
    shor_vulnerable: bool
    alpha: float
    beta: float
    time_factor: float
    migration_factor: float
    sensitivity_factor: float
    exposure_factor: float
    compliance_factor: float
    layer_score: float          # 0..1
    band: RiskBand


@dataclass
class Recommendation:
    """Output of the recommendation engine (Section 11 of the design doc) for one finding."""

    finding_id: str
    primary: str
    fallback: str
    reason: str
    est_migration_effort: str   # "low" | "medium" | "high"
