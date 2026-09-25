"""
ECDAT -- CBOM -> CycloneDX 1.6 export (cryptographic-asset profile).
No external dependency; hand-builds a spec-shaped BOM using the
documented crypto-asset extension fields (bomFormat, cryptoProperties).
"""

import uuid
from datetime import datetime, timezone

ASSET_TYPE_MAP = {
    "Algorithm": "algorithm",
    "Hash Function": "algorithm",
    "Key": "related-crypto-material",
    "Certificate": "certificate",
    "Protocol": "protocol",
    "Library": "related-crypto-material",
}


def _crypto_properties(entry: dict) -> dict:
    asset_type = ASSET_TYPE_MAP.get(entry["cbom_category"], "algorithm")
    props = {"assetType": asset_type}

    if asset_type == "algorithm":
        props["algorithmProperties"] = {
            "primitive": "hash" if entry["cbom_category"] == "Hash Function" else "unknown",
            "parameterSetIdentifier": str(entry.get("key_size") or ""),
        }
    elif asset_type == "certificate":
        props["certificateProperties"] = {
            "signatureAlgorithmRef": entry["algorithm"],
        }
    elif asset_type == "protocol":
        props["protocolProperties"] = {"protocolType": "tls", "version": entry["algorithm"]}
    elif asset_type == "related-crypto-material":
        props["relatedCryptoMaterialProperties"] = {
            "type": "private-key" if entry["cbom_category"] == "Key" else "unknown",
            "size": entry.get("key_size"),
        }

    return props


def cbom_entry_to_component(entry: dict) -> dict:
    name = entry["algorithm"] if entry["algorithm"] != "UNSPECIFIED" else (entry.get("library") or "unknown")
    component = {
        "type": "cryptographic-asset",
        "bom-ref": entry["cbom_entry_id"],
        "name": name,
        "cryptoProperties": _crypto_properties(entry),
        "evidence": {
            "occurrences": [{"location": occ["file_path"]} for occ in entry["occurrences"]]
        },
    }
    if entry.get("recommendation"):
        component["properties"] = [
            {"name": "ecdat:recommendedAlternative", "value": entry["recommendation"]["recommended_alternative"]}
        ]
    return component


def cbom_to_cyclonedx(cbom_output: dict) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "ECDAT", "version": cbom_output.get("cbom_version", "1.0")}
                ]
            },
        },
        "components": [cbom_entry_to_component(e) for e in cbom_output["components"]],
    }