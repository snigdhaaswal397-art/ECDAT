"""
Top-level entry point. This is the piece ECDAT actually calls: feed it the
scanner's existing finding dicts, get back the same dicts with a `risk`
and `recommendation` block attached, matching the JSON schema in the
design doc's Section 8.1.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List

from .config import EngineConfig, WEIGHT_PRESETS
from .models import DeviceClass, Finding, Purpose, Sensitivity
from .recommend import recommend
from .scoring import aggregate_system_score, score_finding


class RiskEngine:
    """
    Usage:
        engine = RiskEngine()                      # default weights
        engine = RiskEngine(profile="iot")          # IoT-preset weights

        enriched = engine.process_findings(scanner_findings)  # list[dict]
        summary  = engine.summarize(enriched)                 # dict
    """

    def __init__(self, config: EngineConfig | None = None, profile: str | None = None):
        if config is not None and profile is not None:
            raise ValueError("Pass either config or profile, not both.")
        if profile is not None:
            if profile not in WEIGHT_PRESETS:
                raise KeyError(f"Unknown profile '{profile}'. Known: {list(WEIGHT_PRESETS)}")
            config = EngineConfig(weights=WEIGHT_PRESETS[profile])
        self.config = config or EngineConfig()

    # -- JSON dict <-> Finding -------------------------------------------------

    @staticmethod
    def _finding_from_dict(d: Dict[str, Any]) -> Finding:
        """Tolerant loader: pulls known fields, ignores/keeps the rest in `extra`."""
        known_enum_fields = {
            "purpose": (Purpose, Purpose.UNKNOWN),
            "sensitivity": (Sensitivity, Sensitivity.MODERATE),
            "device_class": (DeviceClass, DeviceClass.STANDARD),
        }
        kwargs: Dict[str, Any] = {}
        field_names = Finding.__dataclass_fields__.keys()
        extra = {}

        for key, value in d.items():
            if key in known_enum_fields:
                enum_cls, default = known_enum_fields[key]
                try:
                    kwargs[key] = enum_cls(value)
                except ValueError:
                    kwargs[key] = default
            elif key in field_names:
                kwargs[key] = value
            else:
                extra[key] = value

        kwargs.setdefault("extra", {})
        kwargs["extra"].update(extra)
        return Finding(**kwargs)

    # -- public API --------------------------------------------------------

    def process_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Take ECDAT's existing list of finding dicts, return the same list
        with `risk` and `recommendation` sub-dicts added to each entry.
        Original fields are preserved untouched.
        """
        enriched = []
        for raw in findings:
            finding = self._finding_from_dict(raw)
            risk = score_finding(finding, self.config)
            rec = recommend(finding, risk)

            out = dict(raw)  # keep every original ECDAT field as-is
            out["risk"] = {
                "layer": risk.layer.value,
                "shor_vulnerable": risk.shor_vulnerable,
                "attenuation": {"alpha": risk.alpha, "beta": risk.beta},
                "factors": {
                    "time": risk.time_factor,
                    "migration": risk.migration_factor,
                    "sensitivity": risk.sensitivity_factor,
                    "exposure": risk.exposure_factor,
                    "compliance": risk.compliance_factor,
                },
                "layer_score": risk.layer_score,
                "band": risk.band.value,
            }
            out["recommendation"] = asdict(rec)
            del out["recommendation"]["finding_id"]  # redundant with the top-level id
            enriched.append(out)
        return enriched

    def summarize(self, enriched_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """System-level overall_score + priority_layer (Section 5)."""
        from .models import Layer, RiskBand, RiskScore  # local import to avoid cycle at module load

        scores = []
        for f in enriched_findings:
            r = f["risk"]
            scores.append(
                RiskScore(
                    finding_id=f.get("finding_id", ""),
                    layer=Layer(r["layer"]),
                    shor_vulnerable=r["shor_vulnerable"],
                    alpha=r["attenuation"]["alpha"],
                    beta=r["attenuation"]["beta"],
                    time_factor=r["factors"]["time"],
                    migration_factor=r["factors"]["migration"],
                    sensitivity_factor=r["factors"]["sensitivity"],
                    exposure_factor=r["factors"]["exposure"],
                    compliance_factor=r["factors"]["compliance"],
                    layer_score=r["layer_score"],
                    band=RiskBand(r["band"]),
                )
            )
        return aggregate_system_score(scores)
