"""
Recommendation engine (Section 11 of the design doc).

Deliberately simple: a lookup rule, not an optimiser. This is the
"first working version" the design doc describes -- a natural upgrade
path later is to swap `recommend()`'s internals for a real
benchmark-and-validate pipeline (measure on the actual target device,
rank, confirm with a live handshake) without changing its signature.
"""

from __future__ import annotations

from .config import (
    DEFAULT_KEM_FAMILY,
    DEFAULT_SIGNATURE_FAMILY,
    KEM_VARIANTS_BY_STRENGTH,
    LONG_TERM_SIGNATURE_FAMILY,
    SIGNATURE_VARIANTS_BY_STRENGTH,
)
from .models import DeviceClass, Finding, Purpose, Recommendation, RiskBand, RiskScore

_HIGH_RISK_BANDS = (RiskBand.HIGH, RiskBand.CRITICAL)


def _candidate_family(finding: Finding) -> str:
    if finding.purpose in (Purpose.KEY_EXCHANGE, Purpose.ENCRYPTION):
        return DEFAULT_KEM_FAMILY
    if finding.purpose == Purpose.SIGNING:
        # Long-lived signing keys (e.g. root/manufacturer certs) favour the
        # hash-based, longer-term-conservative SLH-DSA family.
        if finding.key_is_long_lived:
            return LONG_TERM_SIGNATURE_FAMILY
        return DEFAULT_SIGNATURE_FAMILY
    # Integrity-only or unknown purpose: default to signatures, since a
    # broken MAC's usual replacement path is a signed/authenticated scheme.
    return DEFAULT_SIGNATURE_FAMILY


def _strength_tier(finding: Finding, risk: RiskScore) -> str:
    base = "light" if finding.device_class == DeviceClass.CONSTRAINED else "standard"
    if risk.band in _HIGH_RISK_BANDS:
        return "strong"
    return base


def _variant_for(family: str, tier: str) -> str:
    if family == DEFAULT_KEM_FAMILY:
        return KEM_VARIANTS_BY_STRENGTH[tier]
    if family in (DEFAULT_SIGNATURE_FAMILY, LONG_TERM_SIGNATURE_FAMILY):
        # SLH-DSA doesn't have the same light/standard/strong ladder in this
        # simplified table -- fall back to the ML-DSA ladder's naming, but
        # keep the SLH-DSA family name for clarity in the output.
        base_variant = SIGNATURE_VARIANTS_BY_STRENGTH[tier]
        if family == LONG_TERM_SIGNATURE_FAMILY:
            return f"{LONG_TERM_SIGNATURE_FAMILY} (SLH-DSA-128s equivalent tier: {tier})"
        return base_variant
    return family


def _fallback_for(primary_family: str) -> str:
    """Diversification: recommend a different family as fallback so a
    single future break doesn't take out both the primary and the backup."""
    if primary_family == DEFAULT_KEM_FAMILY:
        return "Hybrid X25519 + ML-KEM-1024 (classical+PQC diversification)"
    if primary_family in (DEFAULT_SIGNATURE_FAMILY, LONG_TERM_SIGNATURE_FAMILY):
        other = LONG_TERM_SIGNATURE_FAMILY if primary_family == DEFAULT_SIGNATURE_FAMILY else DEFAULT_SIGNATURE_FAMILY
        return f"{other} (different mathematical family for diversification)"
    return "Hybrid classical+PQC alternative"


def _effort_estimate(finding: Finding, risk: RiskScore) -> str:
    if finding.migration_effort_years is None:
        return "unknown"
    if finding.migration_effort_years <= 0.5:
        return "low"
    if finding.migration_effort_years <= 1.5:
        return "medium"
    return "high"


def recommend(finding: Finding, risk: RiskScore) -> Recommendation:
    """Produce a primary + fallback PQC recommendation for one finding."""
    # alpha == beta == 0 is how classify_algorithm() marks an already-PQC-safe
    # algorithm (see attenuation.py) -- nothing to recommend replacing.
    if risk.alpha == 0.0 and risk.beta == 0.0:
        return Recommendation(
            finding_id=finding.finding_id,
            primary=finding.algorithm,
            fallback="none needed",
            reason="already quantum-safe (PQC algorithm detected)",
            est_migration_effort="none",
        )

    family = _candidate_family(finding)
    tier = _strength_tier(finding, risk)
    primary = _variant_for(family, tier)
    fallback = _fallback_for(family)

    reason_parts = [f"{risk.band.value} risk band"]
    if finding.internet_facing:
        reason_parts.append("internet-facing")
    if finding.device_class == DeviceClass.CONSTRAINED:
        reason_parts.append("constrained device")
    reason = " + ".join(reason_parts)

    return Recommendation(
        finding_id=finding.finding_id,
        primary=primary,
        fallback=fallback,
        reason=reason,
        est_migration_effort=_effort_estimate(finding, risk),
    )
