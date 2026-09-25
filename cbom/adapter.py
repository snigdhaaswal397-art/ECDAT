"""
ECDAT -- CBOM Generator output -> Risk Engine input adapter.
"""

CATEGORY_TO_FINDING_TYPE = {
    "Certificate": "certificate",
    "Protocol": "tls_config",
    "Algorithm": "code_call",
    "Hash Function": "code_call",
    "Key": "code_call",
    # "Library" intentionally excluded -- import-signal detections with
    # algorithm="UNSPECIFIED", nothing for the risk engine to score yet.
}

# Path substrings that suggest a finding is internet-facing / high-value.
# Rule-based, on purpose -- a first pass until real exposure data exists.
_INTERNET_HINTS = ("tls", "gateway", "public", "auth", "login", "api", "payment")
_CRITICAL_HINTS = ("payment", "financial", "kms", "vault")


def infer_context(cbom_category: str, algorithm: str, file_path: str) -> dict:
    """Rule-based sensitivity/exposure/purpose tagging from category + path,
    since the scanner doesn't emit this yet (ECDAT open item: Tier 2 tagging)."""
    path_lower = file_path.lower()
    context = {
        "sensitivity": "Moderate",
        "internet_facing": any(h in path_lower for h in _INTERNET_HINTS),
        "data_lifetime_years": 3,
    }

    if any(h in path_lower for h in _CRITICAL_HINTS):
        context["sensitivity"] = "Critical"
        context["data_lifetime_years"] = 12  # long-lived sensitive data: harvest-now-decrypt-later risk
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
    """One CBOM entry -> one Risk Engine finding PER occurrence, so
    location-based factors (internet_facing etc.) stay accurate per file."""
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