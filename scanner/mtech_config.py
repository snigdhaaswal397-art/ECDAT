"""
ECDAT — M_tech Technical Migration Effort Configuration
======================================================

Centralized, deterministic, and configurable rules, thresholds, weights,
fallbacks, and validation constraints for technical migration effort (M_tech) scoring.

Formula:
    M_tech = w1(CA) + w2(DS) + w3(NP)

Constraints:
    1 <= CA <= 5
    1 <= DS <= 5
    1 <= NP <= 5
    0 <= w1, w2, w3 <= 1
    w1 + w2 + w3 == 1.0
    1 <= M_tech <= 5.0
"""

from typing import Dict, Any

# ---------------------------------------------------------------------------
# Architecture Classifications & Baseline Weights
# ---------------------------------------------------------------------------

ARCHITECTURE_SOFTWARE_CENTRIC = "software-centric"
ARCHITECTURE_HARDWARE_IOT_CENTRIC = "hardware/IoT-centric"
ARCHITECTURE_NETWORK_PROTOCOL_CENTRIC = "network/protocol-centric"
ARCHITECTURE_MIXED = "mixed"

BASELINE_WEIGHTS: Dict[str, Dict[str, float]] = {
    ARCHITECTURE_SOFTWARE_CENTRIC: {
        "CA": 0.50,
        "DS": 0.20,
        "NP": 0.30,
    },
    ARCHITECTURE_HARDWARE_IOT_CENTRIC: {
        "CA": 0.25,
        "DS": 0.55,
        "NP": 0.20,
    },
    ARCHITECTURE_NETWORK_PROTOCOL_CENTRIC: {
        "CA": 0.30,
        "DS": 0.20,
        "NP": 0.50,
    },
}

# ---------------------------------------------------------------------------
# Deterministic Fallback Rules for Missing Evidence
# ---------------------------------------------------------------------------

FALLBACK_RULES: Dict[str, Any] = {
    "CA": {
        "default_score": 3,
        "reason": "Missing evidence for crypto-agility; applied deterministic fallback score CA=3.",
    },
    "DS": {
        "default_score": 1,
        "reason": "Missing evidence for hardware/inventory dependencies; applied software-only fallback score DS=1.",
    },
    "NP": {
        "default_score": 1,
        "reason": "Missing evidence for network/protocol constraints; applied low-impact fallback score NP=1.",
    },
    "architecture": {
        "default_classification": ARCHITECTURE_SOFTWARE_CENTRIC,
        "reason": "No specialized hardware/protocol constraints detected; default software-centric architecture applied.",
    },
}

# ---------------------------------------------------------------------------
# Evidence-to-Score Thresholds & Deterministic Rules
# ---------------------------------------------------------------------------

LEGACY_INSECURE_ALGORITHMS = {
    "DES", "3DES", "RC4", "MD5", "SHA-1", "SHA1", "BLOWFISH"
}

MODERN_AGILE_LIBRARIES = {
    "OpenSSL", "Windows CNG", "cryptography", "PyCryptodome", "libsodium",
    "bouncycastle", "Node.js TLS", "Java SSLSocketFactory"
}

# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------

def validate_score(name: str, value: float) -> None:
    """Validate that score is an integer or float between 1 and 5 inclusive."""
    if not (1.0 <= float(value) <= 5.0):
        raise ValueError(f"Invalid {name} score: {value}. Must be between 1 and 5.")


def validate_weights(weights: Dict[str, float]) -> None:
    """Validate that weights are between 0 and 1, and sum exactly to 1.0 (with float tolerance)."""
    for k in ("CA", "DS", "NP"):
        if k not in weights:
            raise ValueError(f"Missing weight key: {k}")
        w = float(weights[k])
        if not (0.0 <= w <= 1.0):
            raise ValueError(f"Weight {k}={w} out of bounds [0.0, 1.0].")

    total = round(sum(float(weights[k]) for k in ("CA", "DS", "NP")), 5)
    if abs(total - 1.0) > 1e-4:
        raise ValueError(f"Weights do not sum to 1.0: CA={weights['CA']}, DS={weights['DS']}, NP={weights['NP']} (sum={total})")


def validate_mtech(mtech: float) -> None:
    """Validate that M_tech is within [1.0, 5.0]."""
    if not (1.0 <= float(mtech) <= 5.0):
        raise ValueError(f"Invalid M_tech value: {mtech}. Must be between 1.0 and 5.0.")
