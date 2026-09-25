"""
Shor-vs-Grover attenuation (Section 6 of the design doc).

Not every "weak" algorithm deserves the same alarm level. RSA/ECC/DH are
fully broken by Shor's algorithm; AES and friends are only weakened by
Grover's algorithm. This module decides which bucket a finding's
algorithm falls into and returns the (alpha, beta) pair that dampens the
score accordingly. PQC-safe algorithms get alpha=beta=0 -- there's
nothing to attenuate because there's no quantum risk left to score.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import (
    AttenuationConfig,
    GROVER_ONLY_ALGORITHMS,
    PQC_SAFE_ALGORITHMS,
    SHOR_VULNERABLE_ALGORITHMS,
)
from .models import Finding


@dataclass
class AttenuationResult:
    shor_vulnerable: bool
    is_pqc_safe: bool
    alpha: float
    beta: float


def _matches_any(algorithm: str, table: tuple) -> bool:
    algorithm_lower = algorithm.lower()
    return any(candidate in algorithm_lower for candidate in table)


def classify_algorithm(finding: Finding, cfg: AttenuationConfig) -> AttenuationResult:
    """
    Decide whether `finding.algorithm` is Shor-vulnerable, Grover-only, or
    already PQC-safe, and return the matching alpha/beta pair.

    Order of checks matters: PQC-safe is checked first so that, e.g., a
    hybrid "X25519+ML-KEM" label doesn't get mis-flagged as Shor-vulnerable
    just because "ECC-family" text appears alongside the PQC name.
    """
    if _matches_any(finding.algorithm, PQC_SAFE_ALGORITHMS):
        return AttenuationResult(shor_vulnerable=False, is_pqc_safe=True, alpha=0.0, beta=0.0)

    if _matches_any(finding.algorithm, SHOR_VULNERABLE_ALGORITHMS):
        return AttenuationResult(
            shor_vulnerable=True, is_pqc_safe=False,
            alpha=cfg.shor_alpha, beta=cfg.shor_beta,
        )

    if _matches_any(finding.algorithm, GROVER_ONLY_ALGORITHMS):
        return AttenuationResult(
            shor_vulnerable=False, is_pqc_safe=False,
            alpha=cfg.grover_alpha, beta=cfg.grover_beta,
        )

    # Unknown algorithm: be conservative and treat like Shor-vulnerable
    # (full urgency) rather than silently under-scoring it. Surface this
    # case in logs/reports so the algorithm table gets extended.
    return AttenuationResult(
        shor_vulnerable=True, is_pqc_safe=False,
        alpha=cfg.shor_alpha, beta=cfg.shor_beta,
    )
