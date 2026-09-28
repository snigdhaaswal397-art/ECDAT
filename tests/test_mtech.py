"""
Tests for M_tech technical migration effort scoring engine, configuration,
and output integration pipeline.
"""

import json
import os
import subprocess
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.mtech_config import (
    validate_score,
    validate_weights,
    validate_mtech,
)
from scanner.mtech_calculator import calculate_mtech


# ---------------------------------------------------------------------------
# 1. Software-only test
# ---------------------------------------------------------------------------

def test_software_only_environment():
    findings = [
        {
            "artifact_type": "algorithm",
            "algorithm": "RSA",
            "library": "cryptography",
            "file_path": "app.py",
            "line_number": 10,
            "detection_method": "ast_call",
            "confidence": 0.95,
        },
        {
            "artifact_type": "hash",
            "algorithm": "SHA-256",
            "library": "hashlib",
            "file_path": "utils.py",
            "line_number": 5,
            "detection_method": "api_pattern",
            "confidence": 0.95,
        },
    ]

    res = calculate_mtech(findings)

    assert res["architecture_classification"] == "software-centric"
    assert res["ratings"]["DS"]["score"] == 1
    assert res["weights"]["CA"] == 0.50
    assert res["weights"]["DS"] == 0.20
    assert res["weights"]["NP"] == 0.30
    assert 1.0 <= res["M_tech"] <= 5.0


# ---------------------------------------------------------------------------
# 2. Hardware / IoT test
# ---------------------------------------------------------------------------

def test_hardware_iot_environment():
    findings = [
        {
            "artifact_type": "hsm",
            "detection_method": "hsm_pattern",
            "evidence": "PKCS#11 HSM Interface",
            "file_path": "crypto_hsm.c",
        },
        {
            "artifact_type": "firmware",
            "detection_method": "firmware_file_extension",
            "evidence": "Firmware binary image",
            "file_path": "device.fw",
        },
    ]

    res = calculate_mtech(findings)

    assert res["architecture_classification"] == "hardware/IoT-centric"
    assert res["ratings"]["DS"]["score"] >= 4
    assert res["weights"]["CA"] == 0.25
    assert res["weights"]["DS"] == 0.55
    assert res["weights"]["NP"] == 0.20


# ---------------------------------------------------------------------------
# 3. Network / Protocol test
# ---------------------------------------------------------------------------

def test_network_protocol_environment():
    findings = [
        {
            "artifact_type": "packet_constraint",
            "detection_method": "packet_mtu_pattern",
            "evidence": "Packet MTU constraint: MTU_SIZE = 1280",
            "file_path": "net_config.h",
        },
        {
            "artifact_type": "packet_constraint",
            "detection_method": "packet_mtu_pattern",
            "evidence": "Fixed Frame / MTU Constraint",
            "file_path": "net_driver.c",
        },
    ]

    res = calculate_mtech(findings)

    assert res["architecture_classification"] == "network/protocol-centric"
    assert res["ratings"]["NP"]["score"] >= 4
    assert res["weights"]["CA"] == 0.30
    assert res["weights"]["DS"] == 0.20
    assert res["weights"]["NP"] == 0.50


# ---------------------------------------------------------------------------
# 4. Mixed architecture test
# ---------------------------------------------------------------------------

def test_mixed_architecture_environment():
    findings = [
        {
            "artifact_type": "hsm",
            "detection_method": "hsm_pattern",
            "evidence": "PKCS#11 HSM Interface",
            "file_path": "hsm.c",
        },
        {
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "library": "OpenSSL",
            "file_path": "app.py",
            "detection_method": "ast_call",
        },
        {
            "artifact_type": "protocol",
            "protocol": "TLS 1.3",
            "detection_method": "api_pattern",
            "file_path": "server.py",
        },
    ]

    res = calculate_mtech(findings)

    assert res["architecture_classification"] == "mixed"
    weights = res["weights"]

    assert 0.0 <= weights["CA"] <= 1.0
    assert 0.0 <= weights["DS"] <= 1.0
    assert 0.0 <= weights["NP"] <= 1.0
    assert round(sum(weights.values()), 2) == 1.00


# ---------------------------------------------------------------------------
# 5. CA boundary tests
# ---------------------------------------------------------------------------

def test_ca_boundaries():
    # CA = 1 (Highly Agile: Centralized modern API / config-driven selection)
    agile_findings = [
        {
            "artifact_type": "protocol",
            "protocol": "TLS 1.3",
            "library": "OpenSSL",
            "detection_method": "api_pattern",
            "file_path": "gateway.py",
        }
    ]
    res_agile = calculate_mtech(agile_findings)
    assert res_agile["ratings"]["CA"]["score"] == 1

    # CA = 5 (Very Low Agility: Custom crypto implementation)
    custom_findings = [
        {
            "artifact_type": "algorithm",
            "algorithm": "CUSTOM_XOR_CIPHER",
            "detection_method": "custom_crypto",
            "evidence": "Hand-rolled cipher implementation",
            "file_path": "my_cipher.c",
        }
    ]
    res_custom = calculate_mtech(custom_findings)
    assert res_custom["ratings"]["CA"]["score"] == 5


# ---------------------------------------------------------------------------
# 6. DS boundary tests
# ---------------------------------------------------------------------------

def test_ds_boundaries():
    # Software-only -> DS = 1
    sw_findings = [
        {
            "artifact_type": "algorithm",
            "algorithm": "RSA",
            "file_path": "main.py",
            "detection_method": "ast_call",
        }
    ]
    res_sw = calculate_mtech(sw_findings)
    assert res_sw["ratings"]["DS"]["score"] == 1

    # Multiple HSMs & hardware -> DS = 5
    hsm_findings = [
        {"artifact_type": "hsm", "evidence": "HSM 1", "file_path": "hsm1.c"},
        {"artifact_type": "hsm", "evidence": "HSM 2", "file_path": "hsm2.c"},
        {"artifact_type": "embedded_iot", "evidence": "FreeRTOS", "file_path": "main.c"},
    ]
    res_hsm = calculate_mtech(hsm_findings)
    assert res_hsm["ratings"]["DS"]["score"] == 5


# ---------------------------------------------------------------------------
# 7. NP boundary tests
# ---------------------------------------------------------------------------

def test_np_boundaries():
    # NP = 1 (Low Impact: standard flexible software protocols)
    sw_proto = [
        {
            "artifact_type": "protocol",
            "protocol": "TLS 1.3",
            "file_path": "app.py",
            "detection_method": "api_pattern",
        }
    ]
    res_low = calculate_mtech(sw_proto)
    assert res_low["ratings"]["NP"]["score"] <= 2

    # NP = 5 (High Impact: strict MTU and embedded packet buffer limits)
    strict_net = [
        {
            "artifact_type": "packet_constraint",
            "detection_method": "packet_mtu_pattern",
            "evidence": "Strict MTU 1280 constraint",
            "file_path": "net.c",
        },
        {
            "artifact_type": "embedded_iot",
            "evidence": "Embedded OS",
            "file_path": "board.c",
        },
    ]
    res_high = calculate_mtech(strict_net)
    assert res_high["ratings"]["NP"]["score"] == 5


# ---------------------------------------------------------------------------
# 8. Weight validation tests
# ---------------------------------------------------------------------------

def test_weight_validation():
    # Sum != 1
    with pytest.raises(ValueError, match="Weights do not sum to 1.0"):
        validate_weights({"CA": 0.50, "DS": 0.50, "NP": 0.50})

    # Value out of bounds (> 1.0)
    with pytest.raises(ValueError, match="out of bounds"):
        validate_weights({"CA": 1.2, "DS": 0.0, "NP": -0.2})

    # Negative value
    with pytest.raises(ValueError, match="out of bounds"):
        validate_weights({"CA": 0.5, "DS": 0.6, "NP": -0.1})

    # Valid weights
    validate_weights({"CA": 0.50, "DS": 0.20, "NP": 0.30})


def test_score_validation():
    with pytest.raises(ValueError, match="Invalid CA score"):
        validate_score("CA", 0)

    with pytest.raises(ValueError, match="Invalid DS score"):
        validate_score("DS", 6)

    validate_score("CA", 1)
    validate_score("CA", 5)


def test_mtech_validation():
    with pytest.raises(ValueError, match="Invalid M_tech value"):
        validate_mtech(0.5)

    with pytest.raises(ValueError, match="Invalid M_tech value"):
        validate_mtech(5.5)

    validate_mtech(3.10)


# ---------------------------------------------------------------------------
# 9. Missing evidence & fallback tests
# ---------------------------------------------------------------------------

def test_missing_evidence_handling():
    res = calculate_mtech([])

    assert res["architecture_classification"] == "software-centric"
    assert res["ratings"]["CA"]["score"] == 3
    assert res["ratings"]["DS"]["score"] == 1
    assert res["ratings"]["NP"]["score"] == 1
    assert len(res["missing_evidence"]) > 0
    assert len(res["uncertainty"]) > 0


# ---------------------------------------------------------------------------
# 10. Reproducibility test
# ---------------------------------------------------------------------------

def test_reproducibility():
    findings = [
        {
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "file_path": "app.py",
            "line_number": 12,
            "detection_method": "ast_call",
            "confidence": 0.95,
        },
        {
            "artifact_type": "protocol",
            "protocol": "TLS 1.2",
            "file_path": "server.py",
            "line_number": 40,
            "detection_method": "api_pattern",
            "confidence": 0.95,
        },
    ]

    r1 = calculate_mtech(findings)
    r2 = calculate_mtech(findings)

    assert r1 == r2


# ---------------------------------------------------------------------------
# 11. Pipeline & Output Integration test
# ---------------------------------------------------------------------------

def test_scanner_output_integration(tmp_path):
    

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("import hashlib\nh = hashlib.sha256(b'test')\n")

    output_json = tmp_path / "scanner_output.json"
    mtech_json = tmp_path / "mtech_result.json"

    project_root = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

    run_res = subprocess.run(
    [
        sys.executable,
        "-m",
        "scanner.scanner",
        str(src_dir),
        "-o",
        str(output_json),
    ],
    cwd=project_root,
    capture_output=True,
    text=True,
    timeout=60,
)

    assert run_res.returncode == 0, run_res.stderr

    # Check raw scanner output exists and is non-empty
    assert output_json.exists()
    with open(output_json, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    assert isinstance(raw_data, list)

    # Check mtech_result.json exists and has valid schema
    assert mtech_json.exists()
    with open(mtech_json, "r", encoding="utf-8") as f:
        mtech_data = json.load(f)

    assert "architecture_classification" in mtech_data
    assert "ratings" in mtech_data
    assert "CA" in mtech_data["ratings"]
    assert "DS" in mtech_data["ratings"]
    assert "NP" in mtech_data["ratings"]
    assert "weights" in mtech_data
    assert "M_tech" in mtech_data
    assert 1.0 <= mtech_data["M_tech"] <= 5.0
