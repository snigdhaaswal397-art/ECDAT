"""
Tests for python_detector.py.

Structure follows the spec's testing requirement (section 24): every
detector needs BOTH positive examples (real crypto usage that should be
caught) AND negative examples (comments/strings/imports that should NOT be
reported as confirmed usage). The negative tests are what protect against
false positives — arguably more important than the positive tests, since a
security tool that over-reports is one nobody trusts.

Run with: python -m pytest tests/test_python_detector.py -v
(or just: python tests/test_python_detector.py, see the __main__ block)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python_detector import scan_python_file


def _scan_source(source: str) -> list[dict]:
    """Helper: write `source` to a temp .py file and scan it."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        path = f.name
    try:
        return scan_python_file(path)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# POSITIVE examples — real usage, must be detected with high confidence
# ---------------------------------------------------------------------------

def test_rsa_generate_detected_with_key_size():
    findings = _scan_source("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
    calls = [f for f in findings if f["detection_method"] == "ast_call"]
    assert len(calls) == 1
    assert calls[0]["algorithm"] == "RSA"
    assert calls[0]["key_size"] == 2048
    assert calls[0]["confidence"] == 0.95


def test_hashlib_sha256_detected():
    findings = _scan_source("import hashlib\nh = hashlib.sha256(b'data')\n")
    calls = [f for f in findings if f["detection_method"] == "ast_call"]
    assert len(calls) == 1
    assert calls[0]["algorithm"] == "SHA-256"


def test_rsa_key_size_via_kwarg():
    findings = _scan_source(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )
    calls = [f for f in findings if f["detection_method"] == "ast_call"]
    assert calls[0]["key_size"] == 4096


# ---------------------------------------------------------------------------
# NEGATIVE examples — must NOT be reported as confirmed usage
# ---------------------------------------------------------------------------

def test_comment_mentioning_rsa_is_not_a_detection():
    findings = _scan_source("# RSA is an old algorithm, we should migrate\nx = 1\n")
    assert len(findings) == 0


def test_string_literal_is_not_a_detection():
    findings = _scan_source('print("RSA")\n')
    assert len(findings) == 0


def test_bare_import_is_low_confidence_not_confirmed_usage():
    """
    `import hashlib` alone must NOT be reported as SHA-256 usage — this is
    the core false-positive-control rule from section 8 of the spec.
    """
    findings = _scan_source("import hashlib\n")
    assert len(findings) == 1
    assert findings[0]["detection_method"] == "ast_import"
    assert findings[0]["algorithm"] == "UNSPECIFIED"
    assert findings[0]["confidence"] < 0.5  # clearly weaker than a confirmed call


def test_import_from_crypto_is_import_signal_not_rsa_usage():
    findings = _scan_source("from Crypto.PublicKey import RSA\n")
    assert len(findings) == 1
    assert findings[0]["artifact_type"] == "import_signal"
    assert findings[0]["algorithm"] == "UNSPECIFIED"


def test_key_size_never_guessed_when_not_explicit():
    """AES.new(key, mode) has no explicit numeric key size — key_size must stay None."""
    findings = _scan_source("from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_EAX)\n")
    calls = [f for f in findings if f["detection_method"] == "ast_call"]
    assert calls[0]["key_size"] is None


def test_unrelated_variable_named_rsa_is_not_detected():
    findings = _scan_source("rsa_flag = True\nif rsa_flag:\n    pass\n")
    assert len(findings) == 0


def test_syntax_error_file_does_not_crash_scanner():
    """A malformed Python file must be skipped, not raise (spec section 21)."""
    findings = _scan_source("def broken(:\n    this is not valid python\n")
    assert findings == []


if __name__ == "__main__":
    # Minimal runner so this works even without pytest installed.
    import traceback
    tests = [(name, fn) for name, fn in list(globals().items())
              if name.startswith("test_") and callable(fn)]
    passed, failed = 0, 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except AssertionError:
            print(f"  FAIL  {name}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
