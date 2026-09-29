"""
ECDAT -- CBOM Generator output -> Risk Engine input adapter.
"""

from recommendation_db import get_recommendation, get_category_level_recommendation

CATEGORY_TO_FINDING_TYPE = {
    "Certificate": "certificate",
    "Protocol": "tls_config",
    "Algorithm": "code_call",
    "Hash Function": "code_call",
    "Key": "code_call",
    # "Library" intentionally excluded -- import-signal detections with
    # algorithm="UNSPECIFIED", nothing for the risk engine to score yet.
}

_INTERNET_HINTS = ("tls", "gateway", "public", "auth", "login", "api", "payment")
_CRITICAL_HINTS = ("payment", "financial", "kms", "vault")


def infer_context(cbom_category: str, algorithm: str, file_path: str) -> dict:
    path_lower = file_path.lower()
    context = {
        "sensitivity": "Moderate",
        "internet_facing": any(h in path_lower for h in _INTERNET_HINTS),
        "data_lifetime_years": 3,
    }

    if any(h in path_lower for h in _CRITICAL_HINTS):
        context["sensitivity"] = "Critical"
        context["data_lifetime_years"] = 12
    elif context["internet_facing"]:
        context["sensitivity"] = "High"
        context["data_lifetime_years"] = 6

    if cbom_category in ("Certificate", "Protocol"):
        context["purpose"] = "key_exchange"
    elif cbom_category == "Hash Function":
        context["purpose"] = "integrity"
    elif cbom_category == "Key":
        context["purpose"] = "signing" if algorithm.upper() in ("ECDSA", "DSA", "ED25519") else "encryption"
    else:
        context["purpose"] = "encryption"

    return context


def cbom_entry_to_findings(entry: dict) -> list[dict]:
    finding_type = CATEGORY_TO_FINDING_TYPE.get(entry["cbom_category"])
    if finding_type is None:
        return []

    findings = []
    for i, occ in enumerate(entry["occurrences"]):
        finding = {
            "finding_id": f"{entry['cbom_entry_id']}_{i}",
            "finding_type": finding_type,
            "algorithm": entry["algorithm"],
            "location": occ["file_path"],
            "key_size": entry.get("key_size"),
            "confidence": occ["confidence"],
        }
        finding.update(infer_context(entry["cbom_category"], entry["algorithm"], occ["file_path"]))
        findings.append(finding)
    return findings


def cbom_to_risk_input(cbom_output: dict) -> list[dict]:
    findings = []
    skipped = 0
    for entry in cbom_output["components"]:
        entry_findings = cbom_entry_to_findings(entry)
        if not entry_findings:
            skipped += 1
        findings.extend(entry_findings)
    print(f"[adapter] {len(findings)} findings converted, {skipped} entries skipped (no scoreable algorithm)")
    return findings


def determine_migration_phase(finding: dict) -> str:
    """Determine where a finding sits in the migration roadmap,
    based only on data available from a static scan. Validate/Migrate/
    Retire require real-world deployment progress this pipeline has
    no way to know, so they stay as roadmap placeholders, not computed
    values."""
    hybrid_ready_types = {"certificate", "tls_config"}
    if finding.get("finding_type") in hybrid_ready_types:
        return "Hybrid-ready"
    return "Discover & Assess"


def merge_recommendations(cbom_output: dict, enriched: list[dict]) -> list[dict]:
    entry_by_id = {entry["cbom_entry_id"]: entry for entry in cbom_output["components"]}

    final = []
    for finding in enriched:
        f2 = dict(finding)
        f2["migration_phase"] = determine_migration_phase(finding)
        cbom_entry_id = finding["finding_id"].rsplit("_", 1)[0]
        cbom_category = entry_by_id.get(cbom_entry_id, {}).get("cbom_category")

        if finding["algorithm"] != "UNSPECIFIED":
            f2["db_recommendation"] = get_recommendation(finding["algorithm"])
            f2["db_recommendation_source"] = "algorithm_map"
        else:
            rec = get_category_level_recommendation(cbom_category)
            f2["db_recommendation"] = rec
            f2["db_recommendation_source"] = "category_fallback" if rec else "none"
        final.append(f2)
    return final