"""
Unit tests for Semgrep detector.
"""

import os
import tempfile
from scanner.detectors.semgrep_detector import scan_with_semgrep


def test_semgrep_weak_des():
    content = """
from Crypto.Cipher import DES

cipher = DES.new(key, DES.MODE_ECB)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_with_semgrep(f_path)
        des_finding = next((r for r in results if r.get("algorithm") == "DES"), None)
        assert des_finding is not None
        assert des_finding.get("detection_method") == "semgrep"
        assert des_finding.get("warning_type") == "deprecated_algorithm"
    finally:
        os.unlink(f_path)


def test_semgrep_rsa_and_sha256():
    content = """
import hashlib
h = hashlib.sha256(b"test").hexdigest()
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_with_semgrep(f_path)
        sha_finding = next((r for r in results if r.get("algorithm") == "SHA-256"), None)
        assert sha_finding is not None
        assert sha_finding.get("detection_method") == "semgrep"
    finally:
        os.unlink(f_path)
