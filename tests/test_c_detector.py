"""
test_c_detector.py
==================
Tests for C / OpenSSL header and function call detection.
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.detectors.c_detector import scan_c_file


def _scan_source(source: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(source)
        path = f.name
    try:
        return scan_c_file(path)
    finally:
        os.unlink(path)


def test_c_openssl_headers_detected_as_import_signal():
    findings = _scan_source("#include <openssl/rsa.h>\n#include <openssl/evp.h>\n")
    imports = [f for f in findings if f["artifact_type"] == "import_signal"]
    assert len(imports) == 2
    assert imports[0]["confidence"] < 0.5


def test_c_rsa_generate_key_detected():
    findings = _scan_source("RSA *r = RSA_generate_key(2048, 65537, NULL, NULL);\n")
    calls = [f for f in findings if f["artifact_type"] == "algorithm"]
    assert len(calls) == 1
    assert calls[0]["algorithm"] == "RSA"
    assert calls[0]["key_size"] == 2048
    assert calls[0]["confidence"] == 0.70


def test_c_md5_and_sha_detected():
    findings = _scan_source("MD5(data, len, md);\nEVP_sha256();\n")
    hashes = [f for f in findings if f["artifact_type"] == "hash"]
    assert len(hashes) == 2
    assert {h["algorithm"] for h in hashes} == {"MD5", "SHA-256"}
