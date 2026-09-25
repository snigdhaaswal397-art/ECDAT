"""
Unit tests for Static Binary Cryptographic detector.
"""

import os
import tempfile
from scanner.detectors.binary_detector import scan_binary_file


def test_binary_embedded_pem():
    content = b"header\n-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\nfooter"
    with tempfile.NamedTemporaryFile("wb", suffix=".so", delete=False) as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_binary_file(f_path)
        cert_finding = next((r for r in results if r.get("artifact_type") == "certificate"), None)
        assert cert_finding is not None
        assert cert_finding.get("detection_method") == "binary_embedded_cert"
    finally:
        os.unlink(f_path)


def test_binary_malformed():
    content = b"NOT_A_VALID_BINARY_OR_ELF"
    with tempfile.NamedTemporaryFile("wb", suffix=".dll", delete=False) as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_binary_file(f_path)
        assert isinstance(results, list)
    finally:
        os.unlink(f_path)
