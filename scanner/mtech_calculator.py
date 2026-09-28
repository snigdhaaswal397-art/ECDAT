"""
ECDAT — Technical Migration Effort Score (M_tech) Calculator
============================================================

Calculates the Technical Migration Effort score (M_tech) based on scanner evidence:

    M_tech = w1(CA) + w2(DS) + w3(NP)

Where:
    CA = Crypto-Agility Level (1 to 5)
    DS = Architectural Dependency & Inventory Scale (1 to 5)
    NP = Network & Protocol Constraints (1 to 5)

All scores, architecture classifications, and weights are derived deterministically
and automatically from scanner findings without requiring manual enterprise input.
"""

from typing import Any, Dict, List, Optional
import os

from scanner.mtech_config import (
    ARCHITECTURE_SOFTWARE_CENTRIC,
    ARCHITECTURE_HARDWARE_IOT_CENTRIC,
    ARCHITECTURE_NETWORK_PROTOCOL_CENTRIC,
    ARCHITECTURE_MIXED,
    BASELINE_WEIGHTS,
    FALLBACK_RULES,
    LEGACY_INSECURE_ALGORITHMS,
    MODERN_AGILE_LIBRARIES,
    validate_score,
    validate_weights,
    validate_mtech,
)


def calculate_mtech(
    findings: List[Dict[str, Any]],
    scanned_directory: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main entry point to compute M_tech and return the structured result schema
    matching mtech_result.json.
    """

    uncertainty: List[str] = []
    missing_evidence: List[str] = []

    # ---------------------------------------------------------------------------
    # 1. Categorize Findings & Extract Evidence
    # ---------------------------------------------------------------------------

    hardware_findings = [
        f for f in findings
        if f.get("artifact_type") in ("hsm", "embedded_iot", "firmware", "hardware")
    ]

    protocol_findings = [
        f for f in findings
        if f.get("artifact_type") in ("protocol", "packet_constraint")
    ]

    db_crypto_findings = [
        f for f in findings
        if f.get("artifact_type") == "database_crypto"
    ]

    software_findings = [
        f for f in findings
        if f not in hardware_findings and f not in protocol_findings and f not in db_crypto_findings
    ]

    # Collect affected files
    affected_files_all = sorted({
        f.get("file_path") for f in findings if f.get("file_path")
    })

    # ---------------------------------------------------------------------------
    # 2. Architecture Classification
    # ---------------------------------------------------------------------------

    arch_evidence: List[str] = []
    num_hw = len(hardware_findings)
    num_proto = len(protocol_findings)
    num_sw = len(software_findings)

    if num_hw > 0 and num_sw > 0:
        arch_class = ARCHITECTURE_MIXED
        arch_evidence.append(
            f"Detected both hardware/IoT dependencies ({num_hw} artifact(s)) and software components ({num_sw} artifact(s))."
        )
    elif num_hw > 0:
        arch_class = ARCHITECTURE_HARDWARE_IOT_CENTRIC
        arch_evidence.append(
            f"Dominant hardware/IoT evidence detected ({num_hw} artifact(s) found: HSM/firmware/embedded)."
        )
    elif num_proto > 0 and num_proto >= num_sw and any(f.get("artifact_type") == "packet_constraint" for f in protocol_findings):
        arch_class = ARCHITECTURE_NETWORK_PROTOCOL_CENTRIC
        arch_evidence.append(
            f"Dominant network/protocol constraints detected ({num_proto} protocol artifact(s))."
        )
    elif num_sw > 0:
        arch_class = ARCHITECTURE_SOFTWARE_CENTRIC
        arch_evidence.append(
            f"Software-centric environment detected ({num_sw} software artifact(s) found, no hardware/IoT dependencies)."
        )
    else:
        # Missing evidence fallback
        arch_class = FALLBACK_RULES["architecture"]["default_classification"]
        fallback_msg = FALLBACK_RULES["architecture"]["reason"]
        arch_evidence.append(fallback_msg)
        missing_evidence.append("No technical findings discovered in target workspace.")
        uncertainty.append("Architecture classified as software-centric by fallback due to empty findings.")

    # ---------------------------------------------------------------------------
    # 3. Automatic Weight Selection
    # ---------------------------------------------------------------------------

    if arch_class == ARCHITECTURE_MIXED:
        total_ev = num_hw + num_proto + num_sw
        if total_ev > 0:
            p_ca = 0.35 + (0.15 * (num_sw / total_ev))
            p_ds = 0.20 + (0.35 * (num_hw / total_ev))
            p_np = 0.20 + (0.30 * (num_proto / total_ev))
        else:
            p_ca, p_ds, p_np = 0.40, 0.30, 0.30

        norm = p_ca + p_ds + p_np
        w_ca = round(p_ca / norm, 2)
        w_ds = round(p_ds / norm, 2)
        w_np = round(1.0 - w_ca - w_ds, 2)
        weights = {"CA": w_ca, "DS": w_ds, "NP": w_np}
    else:
        weights = dict(BASELINE_WEIGHTS[arch_class])

    validate_weights(weights)

    # ---------------------------------------------------------------------------
    # 4. Crypto-Agility (CA) Rating
    # ---------------------------------------------------------------------------

    ca_evidence: List[str] = []
    ca_affected: List[str] = []

    has_custom_crypto = any(f.get("detection_method") == "custom_crypto" for f in findings)
    has_db_crypto = len(db_crypto_findings) > 0
    has_firmware_crypto = any(f.get("artifact_type") == "firmware" for f in findings)

    legacy_found = [
        f for f in findings
        if (f.get("algorithm") or "").upper() in LEGACY_INSECURE_ALGORITHMS
    ]

    modern_found = [
        f for f in findings
        if f.get("library") in MODERN_AGILE_LIBRARIES
    ]

    hardcoded_calls = [
        f for f in findings
        if f.get("detection_method") in ("ast_call", "semgrep", "treesitter_call", "c_ast_call")
    ]

    config_driven = [
        f for f in findings
        if f.get("detection_method") in ("config_directive", "api_pattern")
    ]

    if not findings:
        ca_score = FALLBACK_RULES["CA"]["default_score"]
        ca_reason = FALLBACK_RULES["CA"]["reason"]
        missing_evidence.append("No crypto findings detected to evaluate Crypto-Agility.")
        uncertainty.append("Applied CA=3 fallback score.")
    elif has_custom_crypto or has_firmware_crypto:
        ca_score = 5
        ca_reason = "Very low agility: custom cryptographic algorithm implementation or firmware-level cryptography detected."
        for f in findings:
            if f.get("detection_method") == "custom_crypto" or f.get("artifact_type") == "firmware":
                ca_evidence.append(f"Custom/firmware crypto in {f.get('file_path')}: {f.get('evidence') or f.get('code_snippet')}")
                if f.get("file_path"):
                    ca_affected.append(f.get("file_path"))
    elif has_db_crypto:
        ca_score = 5
        ca_reason = "Very low agility: database-level cryptographic logic detected."
        for f in db_crypto_findings:
            ca_evidence.append(f"Database crypto in {f.get('file_path')}: {f.get('evidence') or f.get('code_snippet')}")
            if f.get("file_path"):
                ca_affected.append(f.get("file_path"))
    elif len(legacy_found) > 0:
        ca_score = 4
        ca_reason = "Low agility: hardcoded legacy/insecure cryptographic algorithms (e.g. DES, MD5, SHA-1) detected."
        for f in legacy_found:
            ca_evidence.append(f"Legacy cipher '{f.get('algorithm')}' in {f.get('file_path', 'unknown')}")
            if f.get("file_path"):
                ca_affected.append(f.get("file_path"))
    elif len(hardcoded_calls) > 3:
        ca_score = 3
        ca_reason = "Moderate agility: cryptography is used via standard libraries but multiple hardcoded algorithm calls are scattered across source files."
        for f in hardcoded_calls[:5]:
            ca_evidence.append(f"Hardcoded algorithm '{f.get('algorithm')}' at {f.get('file_path')}:{f.get('line_number')}")
            if f.get("file_path"):
                ca_affected.append(f.get("file_path"))
    elif len(modern_found) > 0 or len(config_driven) > 0:
        if len(hardcoded_calls) > 0:
            ca_score = 2
            ca_reason = "Good agility: standard modern crypto libraries used with localized algorithm selections."
            for f in modern_found + config_driven:
                ca_evidence.append(f"Standard library/config '{f.get('library') or f.get('protocol')}' in {f.get('file_path')}")
                if f.get("file_path"):
                    ca_affected.append(f.get("file_path"))
        else:
            ca_score = 1
            ca_reason = "Highly agile: cryptography managed via centralized modern APIs and configuration-driven selection with minimal hardcoded logic."
            ca_evidence.append("Centralized modern crypto library APIs and configuration-driven selection detected.")
    else:
        ca_score = 2
        ca_reason = "Moderate-to-good agility: standard software crypto findings with no legacy or custom crypto detected."
        ca_evidence.append("Standard crypto findings with no legacy or custom routines.")

    validate_score("CA", ca_score)
    ca_affected = sorted(set(ca_affected))

    # ---------------------------------------------------------------------------
    # 5. Architectural Dependency & Inventory Scale (DS) Rating
    # ---------------------------------------------------------------------------

    ds_evidence: List[str] = []
    ds_affected: List[str] = []

    if num_hw == 0:
        # SOFTWARE-ONLY SAFEGUARD
        ds_score = 1
        ds_reason = "Low dependency: software-only enterprise with standard software cryptography and no HSM, embedded, IoT, or hardware dependencies."
        ds_evidence.append("Software-only environment confirmed; 0 HSM, IoT, embedded, or specialized hardware artifacts detected.")
    else:
        num_hsm = sum(1 for f in hardware_findings if f.get("artifact_type") == "hsm")
        num_iot = sum(1 for f in hardware_findings if f.get("artifact_type") in ("embedded_iot", "firmware"))

        if num_hsm > 1 or (num_hsm >= 1 and num_iot >= 1):
            ds_score = 5
            ds_reason = "High dependency: multiple HSMs, IoT devices, or physical hardware replacement dependencies detected."
            for f in hardware_findings:
                ds_evidence.append(f"Hardware dependency '{f.get('artifact_type')}' in {f.get('file_path')}: {f.get('evidence')}")
                if f.get("file_path"):
                    ds_affected.append(f.get("file_path"))
        else:
            ds_score = 4
            ds_reason = "Significant dependency: HSM or embedded/IoT device dependency detected requiring hardware/firmware integration."
            for f in hardware_findings:
                ds_evidence.append(f"Hardware/IoT dependency in {f.get('file_path')}: {f.get('evidence')}")
                if f.get("file_path"):
                    ds_affected.append(f.get("file_path"))

    validate_score("DS", ds_score)
    ds_affected = sorted(set(ds_affected))

    # ---------------------------------------------------------------------------
    # 6. Network & Protocol Constraints (NP) Rating
    # ---------------------------------------------------------------------------

    np_evidence: List[str] = []
    np_affected: List[str] = []

    packet_constraints = [
        f for f in protocol_findings
        if f.get("artifact_type") == "packet_constraint"
    ]

    legacy_proto = [
        f for f in protocol_findings
        if (f.get("protocol") or "").upper() in ("TLS 1.0", "TLS 1.1", "SSL", "SSLV3", "SSLV2")
    ]

    modern_proto = [
        f for f in protocol_findings
        if (f.get("protocol") or "").upper() in ("TLS 1.2", "TLS 1.3", "SSH", "TLS")
    ]

    if len(packet_constraints) > 0:
        ds_has_iot = any(f.get("artifact_type") in ("embedded_iot", "firmware") for f in hardware_findings)
        if ds_has_iot or len(packet_constraints) > 1:
            np_score = 5
            np_reason = "High impact: strict packet MTU limits, tight packet buffers, or legacy banking protocol constraints detected."
        else:
            np_score = 4
            np_reason = "Significant impact: fixed frame/packet size or buffer limits detected that may affect larger PQC keys/signatures."

        for f in packet_constraints:
            np_evidence.append(f"Packet/MTU constraint in {f.get('file_path')}: {f.get('evidence') or f.get('code_snippet')}")
            if f.get("file_path"):
                np_affected.append(f.get("file_path"))
    elif len(legacy_proto) > 0:
        np_score = 3
        np_reason = "Moderate impact: legacy TLS/SSL versions (TLS 1.0/1.1/SSLv3) detected in protocol configuration."
        for f in legacy_proto:
            np_evidence.append(f"Legacy protocol '{f.get('protocol')}' in {f.get('file_path')}")
            if f.get("file_path"):
                np_affected.append(f.get("file_path"))
    elif len(modern_proto) > 0:
        np_score = 2
        np_reason = "Low-to-moderate impact: standard TLS 1.2+ / SSH protocol APIs detected with configurable cipher suites."
        for f in modern_proto:
            np_evidence.append(f"Standard protocol '{f.get('protocol')}' in {f.get('file_path')}")
            if f.get("file_path"):
                np_affected.append(f.get("file_path"))
    else:
        np_score = 1
        np_reason = "Low impact: standard flexible software protocols detected with no restrictive packet MTU or buffer limits."
        np_evidence.append("Standard flexible software protocols; no restrictive MTU or packet buffer limits discovered.")

    validate_score("NP", np_score)
    np_affected = sorted(set(np_affected))

    # ---------------------------------------------------------------------------
    # 7. Final M_tech Score Calculation
    # ---------------------------------------------------------------------------

    raw_mtech = (
        (weights["CA"] * ca_score) +
        (weights["DS"] * ds_score) +
        (weights["NP"] * np_score)
    )

    mtech_val = round(raw_mtech, 2)
    validate_mtech(mtech_val)

    # ---------------------------------------------------------------------------
    # 8. Component-Level Ratings
    # ---------------------------------------------------------------------------

    component_ratings: List[Dict[str, Any]] = []
    files_map: Dict[str, List[Dict[str, Any]]] = {}

    for f in findings:
        fp = f.get("file_path") or "general"
        files_map.setdefault(fp, []).append(f)

    for fp, comp_findings in files_map.items():
        comp_name = os.path.basename(fp) if fp != "general" else "general"

        comp_has_legacy = any((f.get("algorithm") or "").upper() in LEGACY_INSECURE_ALGORITHMS for f in comp_findings)
        comp_has_custom = any(f.get("detection_method") == "custom_crypto" for f in comp_findings)

        comp_ca = 5 if comp_has_custom else (4 if comp_has_legacy else 2)
        comp_ds = 4 if any(f.get("artifact_type") in ("hsm", "embedded_iot", "firmware") for f in comp_findings) else 1
        comp_np = 4 if any(f.get("artifact_type") == "packet_constraint" for f in comp_findings) else 1

        comp_mtech = round((weights["CA"] * comp_ca) + (weights["DS"] * comp_ds) + (weights["NP"] * comp_np), 2)

        component_ratings.append({
            "component": comp_name,
            "affected_files": [fp],
            "ratings": {
                "CA": {"score": comp_ca, "reason": f"Component CA score based on {len(comp_findings)} artifact(s)"},
                "DS": {"score": comp_ds, "reason": f"Component DS score based on hardware dependencies"},
                "NP": {"score": comp_np, "reason": f"Component NP score based on protocol constraints"},
            },
            "weights": weights,
            "M_tech": comp_mtech,
        })

    # ---------------------------------------------------------------------------
    # 9. Build Final Output Schema
    # ---------------------------------------------------------------------------

    result: Dict[str, Any] = {
        "architecture_classification": arch_class,
        "architecture_evidence": arch_evidence,
        "ratings": {
            "CA": {
                "score": ca_score,
                "reason": ca_reason,
                "evidence": ca_evidence,
                "affected_components": ca_affected,
            },
            "DS": {
                "score": ds_score,
                "reason": ds_reason,
                "evidence": ds_evidence,
                "affected_components": ds_affected,
            },
            "NP": {
                "score": np_score,
                "reason": np_reason,
                "evidence": np_evidence,
                "affected_components": np_affected,
            },
        },
        "weights": weights,
        "M_tech": mtech_val,
        "uncertainty": uncertainty,
        "missing_evidence": missing_evidence,
        "component_ratings": component_ratings,
    }

    return result
