"""
Tests for c_detector.py.

Same structure as test_python_detector.py: positive examples (real usage)
and negative examples (comments, includes-only) that must NOT be reported
as confirmed usage.

This file did not exist in the uploaded project -- c_detector.py had no
dedicated test coverage at all. Added as part of the scanner audit.

Run with: python -m pytest tests/test_c_detector.py -v
"""

import os
import sys
import tempfile

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


# ---------------------------------------------------------------------------
# POSITIVE examples
# ---------------------------------------------------------------------------


def test_rsa_generate_key_detected_with_key_size():
    findings = _scan_source(
        "#include <openssl/rsa.h>\n"
        "RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);\n"
    )
    calls = [f for f in findings if f["artifact_type"] != "import_signal"]
    assert len(calls) == 1
    assert calls[0]["algorithm"] == "RSA"
    assert calls[0]["key_size"] == 2048


def test_sha256_detected():
    findings = _scan_source(
        "#include <openssl/evp.h>\n"
        "EVP_DigestInit(ctx, EVP_sha256());\n"
    )
    calls = [f for f in findings if f["artifact_type"] != "import_signal"]
    assert any(f["algorithm"] == "SHA-256" for f in calls)


def test_aes_des_detected():
    findings = _scan_source(
        "#include <openssl/aes.h>\n"
        "AES_encrypt(in, out, &key);\n"
        "DES_ecb_encrypt(input, output, ks, DES_ENCRYPT);\n"
    )
    algos = {f["algorithm"] for f in findings if f["artifact_type"] != "import_signal"}
    assert "AES" in algos
    assert "DES" in algos


def test_openssl_header_is_low_confidence_import_signal_only():
    findings = _scan_source("#include <openssl/md5.h>\n")
    assert len(findings) == 1
    assert findings[0]["artifact_type"] == "import_signal"
    assert findings[0]["confidence"] < 0.5
    # a bare #include is NOT actual usage
    assert not any(f["artifact_type"] == "algorithm" for f in findings)


# ---------------------------------------------------------------------------
# NEGATIVE examples -- false-positive guards
# ---------------------------------------------------------------------------


def test_commented_out_line_comment_is_not_detected():
    findings = _scan_source(
        "#include <openssl/md5.h>\n"
        "// MD5(data, len, digest);  -- disabled, do not use\n"
    )
    assert not any(f["artifact_type"] == "algorithm" for f in findings)


def test_commented_out_block_comment_is_not_detected():
    findings = _scan_source(
        "#include <openssl/aes.h>\n"
        "/* AES_encrypt(in, out, &key); -- old approach */\n"
        "int main() { return 0; }\n"
    )
    assert not any(f["artifact_type"] == "algorithm" for f in findings)


def test_multiline_block_comment_does_not_shift_line_numbers():
    findings = _scan_source(
        "/* a comment\n"
        "spanning multiple\n"
        "lines */\n"
        "#include <openssl/evp.h>\n"
        "EVP_DigestInit(ctx, EVP_sha256());\n"
    )
    calls = [f for f in findings if f["artifact_type"] != "import_signal"]
    assert calls[0]["line_number"] == 5


def test_normal_c_code_produces_no_findings():
    findings = _scan_source(
        "#include <stdio.h>\n"
        "int main() {\n"
        "    printf(\"hello world\\n\");\n"
        "    return 0;\n"
        "}\n"
    )
    assert findings == []


def test_unrelated_include_is_not_flagged():
    findings = _scan_source("#include <stdlib.h>\n#include <string.h>\n")
    assert findings == []


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))