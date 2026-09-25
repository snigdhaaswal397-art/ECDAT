"""
Every number a judge, auditor, or teammate might reasonably ask "why this
value?" about lives in this one file. Nothing below is empirically
validated -- these are expert-judgement starting points from the published
QARS literature (Grigaliunas & Bruzgiene 2025; the 2026 enterprise
extension) and NIST SP 1800-38. Treat them as defaults to override per
deployment, not as ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from .models import DeviceClass, Sensitivity


@dataclass
class Weights:
    """w1..w5 in: score = w1*a*T + w2*a*M + w3*b*S + w4*b*E + w5*C  (a=alpha, b=beta)"""
    time_left: float = 0.30        # w1
    migration_effort: float = 0.15  # w2
    sensitivity: float = 0.25       # w3
    exposure: float = 0.20          # w4
    compliance: float = 0.10        # w5

    def validate(self) -> None:
        total = self.time_left + self.migration_effort + self.sensitivity + self.exposure + self.compliance
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total:.4f}")


# Sector-specific weight presets, per the enterprise QARS paper. IoT/embedded
# assets weight timeline higher (long field lifetimes, slow upgrade cycles);
# general enterprise assets weight sensitivity higher.
WEIGHT_PRESETS: Dict[str, Weights] = {
    "iot": Weights(time_left=0.50, migration_effort=0.10, sensitivity=0.20, exposure=0.20, compliance=0.00),
    "enterprise_default": Weights(time_left=0.25, migration_effort=0.15, sensitivity=0.30, exposure=0.20, compliance=0.10),
    "finance": Weights(time_left=0.20, migration_effort=0.10, sensitivity=0.40, exposure=0.20, compliance=0.10),
}


@dataclass
class AttenuationConfig:
    """Alpha turns down time-urgency, beta turns down impact, for Grover-only findings."""
    shor_alpha: float = 1.0
    shor_beta: float = 1.0
    grover_alpha: float = 0.15
    grover_beta: float = 0.30


# Algorithms considered fully broken by Shor's algorithm once a CRQC exists.
# Match is case-insensitive substring against Finding.algorithm.
SHOR_VULNERABLE_ALGORITHMS: Tuple[str, ...] = (
    "rsa", "ecc", "ecdsa", "ecdh", "dh", "dsa", "elgamal",
)

# Algorithms already considered quantum-safe (PQC) -- treated as Shor-safe
# AND given a large exposure discount, since v(a) / R_algo should be ~0 here.
PQC_SAFE_ALGORITHMS: Tuple[str, ...] = (
    "ml-kem", "kyber", "ml-dsa", "dilithium", "slh-dsa", "sphincs",
)

# Symmetric/hash primitives -- Grover-only, never Shor-vulnerable.
GROVER_ONLY_ALGORITHMS: Tuple[str, ...] = (
    "aes", "chacha20", "sha", "hmac", "camellia", "3des", "des",
)

QUANTUM_ARRIVAL_YEAR: int = 2035     # Z: shared org-wide CRQC assumption; revise as estimates shift
CURRENT_YEAR: int = 2026

SENSITIVITY_SCORE: Dict[Sensitivity, float] = {
    Sensitivity.LOW: 0.25,
    Sensitivity.MODERATE: 0.50,
    Sensitivity.HIGH: 0.75,
    Sensitivity.CRITICAL: 1.0,
}

# Migration effort (years) defaults by finding_type, used when a finding
# doesn't specify migration_effort_years itself. Rough starting points only.
DEFAULT_MIGRATION_EFFORT_YEARS: Dict[str, float] = {
    "certificate": 0.5,
    "tls_config": 1.0,
    "code_call": 1.5,
    "container_secret": 0.5,
    "protocol_handshake": 2.0,
}
DEFAULT_MIGRATION_EFFORT_FALLBACK_YEARS: float = 1.0

# Data lifetime (years) default when a finding doesn't specify one.
DEFAULT_DATA_LIFETIME_YEARS: float = 5.0

RISK_BAND_THRESHOLDS: Tuple[Tuple[float, "str"], ...] = (
    (0.30, "low"),
    (0.60, "medium"),
    (0.85, "high"),
    # anything above the last threshold is "critical"
)

# NIST SP 1800-38-style default algorithm families per purpose.
DEFAULT_KEM_FAMILY = "ML-KEM"
DEFAULT_SIGNATURE_FAMILY = "ML-DSA"
LONG_TERM_SIGNATURE_FAMILY = "SLH-DSA"

KEM_VARIANTS_BY_STRENGTH: Dict[str, str] = {
    "light": "ML-KEM-512",
    "standard": "ML-KEM-768",
    "strong": "ML-KEM-1024",
}
SIGNATURE_VARIANTS_BY_STRENGTH: Dict[str, str] = {
    "light": "ML-DSA-44",
    "standard": "ML-DSA-65",
    "strong": "ML-DSA-87",
}


@dataclass
class EngineConfig:
    weights: Weights = field(default_factory=Weights)
    attenuation: AttenuationConfig = field(default_factory=AttenuationConfig)
    quantum_arrival_year: int = QUANTUM_ARRIVAL_YEAR
    current_year: int = CURRENT_YEAR

    def __post_init__(self) -> None:
        self.weights.validate()
