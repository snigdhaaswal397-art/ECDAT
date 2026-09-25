"""
Turns raw Finding fields into the five 0..1 factors used by the scoring
formula. Kept separate from scoring.py so each factor's logic can be
tested and tuned independently.
"""

from __future__ import annotations

import math

from .config import (
    DEFAULT_DATA_LIFETIME_YEARS,
    DEFAULT_MIGRATION_EFFORT_FALLBACK_YEARS,
    DEFAULT_MIGRATION_EFFORT_YEARS,
    SENSITIVITY_SCORE,
    EngineConfig,
)
from .models import Finding


def time_left_factor(finding: Finding, cfg: EngineConfig, steepness: float = 2.0) -> float:
    """
    r(a) = (X + Y) / Z_remaining, squashed into [0, 1] with a logistic curve.

    X = how long the data must stay confidential (data_lifetime_years)
    Y = how long migration will take (migration_effort_years)
    Z_remaining = years left until the shared quantum-arrival assumption

    r > 1 means Mosca's original "too late already" condition is met;
    the logistic pushes T towards 1 as r crosses 1, and towards 0 well
    below it, without a hard step discontinuity.
    """
    x = finding.data_lifetime_years if finding.data_lifetime_years is not None else DEFAULT_DATA_LIFETIME_YEARS
    y = _migration_effort_years(finding)

    z_remaining = max(cfg.quantum_arrival_year - cfg.current_year, 0.1)  # avoid /0
    r = (x + y) / z_remaining

    # logistic squash centred at r=1
    return 1.0 / (1.0 + math.exp(-steepness * (r - 1.0)))


def migration_factor(finding: Finding, cfg: EngineConfig) -> float:
    """
    Simple normalised view of migration effort on its own (separate from
    how it interacts with the deadline in time_left_factor): longer
    estimated migration = higher factor, capped at 1.0 for anything at or
    beyond a 3-year effort estimate.
    """
    y = _migration_effort_years(finding)
    return min(y / 3.0, 1.0)


def sensitivity_factor(finding: Finding) -> float:
    return SENSITIVITY_SCORE[finding.sensitivity]


def exposure_factor(finding: Finding) -> float:
    """
    How readily an attacker could get hold of the ciphertext/material.
    A simple additive heuristic over three boolean signals ECDAT can
    reasonably infer from deployment context; capped at 1.0.
    """
    score = 0.0
    if finding.internet_facing:
        score += 0.6
    if finding.public_registry:
        score += 0.3
    if finding.third_party_api:
        score += 0.3
    return min(score, 1.0)


def compliance_factor(finding: Finding) -> float:
    """
    Placeholder compliance penalty (e.g. NIS2-style regulatory exposure).
    Wire this up to real policy/compliance tags once available; defaulting
    to 0 means it simply drops out of the weighted sum until then.
    """
    return float(finding.extra.get("compliance_score", 0.0))


def _migration_effort_years(finding: Finding) -> float:
    if finding.migration_effort_years is not None:
        return finding.migration_effort_years
    return DEFAULT_MIGRATION_EFFORT_YEARS.get(
        finding.finding_type.lower(), DEFAULT_MIGRATION_EFFORT_FALLBACK_YEARS
    )
