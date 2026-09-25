"""
risk_engine
===========

A small, dependency-free risk-scoring and recommendation layer that sits
downstream of the ECDAT scanner's JSON output.

Typical usage
-------------
    from risk_engine import RiskEngine

    engine = RiskEngine()                     # uses default config
    enriched = engine.process_findings(findings)   # list[dict] in, list[dict] out
    report = engine.summarize(enriched)            # overall + priority layer

See README.md for the full data model and formula reference.
"""

from .engine import RiskEngine
from .models import Finding, RiskScore, Recommendation

__all__ = ["RiskEngine", "Finding", "RiskScore", "Recommendation"]
