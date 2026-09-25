"""
The scoring formula itself (Sections 5-6 of the design doc):

    layer_score = w1*alpha*T + w2*alpha*M + w3*beta*S + w4*beta*E + w5*C

T = time_left_factor, M = migration_factor, S = sensitivity_factor,
E = exposure_factor, C = compliance_factor. alpha dampens the two
time-related terms, beta dampens the two impact-related terms, for
findings that are only Grover-weakened rather than Shor-broken.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from .attenuation import classify_algorithm
from .config import RISK_BAND_THRESHOLDS, EngineConfig
from .factors import (
    compliance_factor,
    exposure_factor,
    migration_factor,
    sensitivity_factor,
    time_left_factor,
)
from .layers import classify_layer
from .models import Finding, Layer, RiskBand, RiskScore


def _band_for(score: float) -> RiskBand:
    for threshold, band_name in RISK_BAND_THRESHOLDS:
        if score <= threshold:
            return RiskBand(band_name)
    return RiskBand.CRITICAL


def score_finding(finding: Finding, cfg: EngineConfig) -> RiskScore:
    """Compute the full RiskScore for a single finding."""
    layer = classify_layer(finding)
    atten = classify_algorithm(finding, cfg.attenuation)

    t = time_left_factor(finding, cfg)
    m = migration_factor(finding, cfg)
    s = sensitivity_factor(finding)
    e = exposure_factor(finding)
    c = compliance_factor(finding)

    w = cfg.weights
    layer_score = (
        w.time_left * atten.alpha * t
        + w.migration_effort * atten.alpha * m
        + w.sensitivity * atten.beta * s
        + w.exposure * atten.beta * e
        + w.compliance * c
    )
    layer_score = max(0.0, min(layer_score, 1.0))

    return RiskScore(
        finding_id=finding.finding_id,
        layer=layer,
        shor_vulnerable=atten.shor_vulnerable,
        alpha=atten.alpha,
        beta=atten.beta,
        time_factor=round(t, 4),
        migration_factor=round(m, 4),
        sensitivity_factor=round(s, 4),
        exposure_factor=round(e, 4),
        compliance_factor=round(c, 4),
        layer_score=round(layer_score, 4),
        band=_band_for(layer_score),
    )


def score_findings(findings: Iterable[Finding], cfg: EngineConfig) -> List[RiskScore]:
    return [score_finding(f, cfg) for f in findings]


def aggregate_system_score(scores: Iterable[RiskScore]) -> Dict[str, object]:
    """
    System-level summary (Section 5): an overall (average) score AND the
    single worst-scoring layer, reported separately so a low average can't
    hide one badly exposed layer.
    """
    scores = list(scores)
    if not scores:
        return {"overall_score": 0.0, "priority_layer": None, "layer_scores": {}}

    by_layer: Dict[Layer, List[float]] = defaultdict(list)
    for s in scores:
        by_layer[s.layer].append(s.layer_score)

    layer_averages = {layer.value: round(sum(vals) / len(vals), 4) for layer, vals in by_layer.items()}
    overall = round(sum(s.layer_score for s in scores) / len(scores), 4)
    priority_layer = max(layer_averages, key=layer_averages.get) if layer_averages else None

    return {
        "overall_score": overall,
        "priority_layer": priority_layer,
        "layer_scores": layer_averages,
    }
