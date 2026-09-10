"""
test_certificate_detector.py
=============================

Standalone pytest test suite for certificate_detector.py.

All fixtures used here are TEST-ONLY, disposable, generated at collection
time (or pre-generated under samples/certificates/) purely for this suite.
None of them are, or were ever, production certificates or keys.

Run with:
    python -m pytest tests/test_certificate_detector.py -v
"""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scanner", "detectors"))

from scanner.detectors.certificate_detector import (  # noqa: E402
    CertificateDetectorError,
    scan_certificate,
    scan_certificate_content,
)

SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "samples", "certificates"
)


def _sample(name: str) -> str:
    return os.path.join(SAMPLES_DIR, name)


def _read(name: str) -> bytes:
    with open(_sample(name), "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# Missing / invalid file handling
# --------------------------------------------------------------------------- #


def test_missing_certificate_file_raises():
    with pytest.raises(CertificateDetectorError):
        scan_certificate(_sample("does_not_exist.pem"))


def test_directory_instead_of_file_raises():
    with pytest.raises(CertificateDetectorError):
        scan_certificate(SAMPLES_DIR)


def test_unsupported_extension_raises():
    with pytest.raises(CertificateDetectorError):
        scan_certificate(_sample("not_a_cert.txt"))


def test_malformed_certificate_raises():
    with pytest.raises(CertificateDetectorError):
        scan_certificate(_sample("malformed_cert.crt"))


def test_malformed_but_pem_labeled_certificate_raises():
    with pytest.raises(CertificateDetectorError):
        scan_certificate(_sample("malformed_but_labeled.pem"))


# --------------------------------------------------------------------------- #
# OpenSSL availability
# --------------------------------------------------------------------------- #


def test_openssl_unavailable_raises_clear_error(monkeypatch):
    import scanner.detectors.certificate_detector as cd

    monkeypatch.setattr(cd, "_openssl_checked", False)
    monkeypatch.setattr(cd, "_openssl_available", False)
    monkeypatch.setattr(cd.shutil, "which", lambda _bin: None)

    with pytest.raises(CertificateDetectorError, match="OpenSSL"):
        scan_certificate(_sample("rsa2048_cert.pem"))


def test_openssl_command_failure_is_wrapped(monkeypatch):
    import scanner.detectors.certificate_detector as cd

    def fake_run(args, input_bytes=None, timeout=cd.OPENSSL_TIMEOUT_SECONDS):
        class FakeResult:
            returncode = 1
            stdout = b""
            stderr = b"unable to load certificate\nsome openssl internal error"
        return FakeResult()

    monkeypatch.setattr(cd, "_run_openssl", fake_run)

    with pytest.raises(CertificateDetectorError):
        scan_certificate(_sample("rsa2048_cert.pem"))


def test_openssl_timeout_raises_certificate_detector_error(monkeypatch):
    import scanner.detectors.certificate_detector as cd

    def fake_run(args, input_bytes=None, timeout=cd.OPENSSL_TIMEOUT_SECONDS):
        raise subprocess.TimeoutExpired(cmd="openssl", timeout=timeout)

    # patch at the subprocess.run level inside _run_openssl instead, to
    # exercise the real timeout-handling code path
    def fake_subprocess_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="openssl", timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr(cd.subprocess, "run", fake_subprocess_run)

    with pytest.raises(CertificateDetectorError, match="timed out"):
        scan_certificate(_sample("rsa2048_cert.pem"))


# --------------------------------------------------------------------------- #
# Valid PEM / RSA certificate
# --------------------------------------------------------------------------- #


def test_valid_pem_certificate_is_detected():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert len(findings) == 1
    assert findings[0]["artifact_type"] == "certificate"


def test_rsa_algorithm_detected():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["algorithm"] == "RSA"


def test_rsa_key_size_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["key_size"] == 2048


def test_rsa4096_key_size_extracted():
    findings = scan_certificate(_sample("rsa4096_cert.pem"))
    assert findings[0]["key_size"] == 4096
    assert findings[0]["algorithm"] == "RSA"


def test_signature_algorithm_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["signature_algorithm"] == "sha256WithRSAEncryption"


def test_signature_algorithm_is_distinct_from_public_key_algorithm():
    findings = scan_certificate(_sample("rsa4096_cert.pem"))
    assert findings[0]["algorithm"] == "RSA"
    assert findings[0]["signature_algorithm"] == "sha384WithRSAEncryption"
    assert findings[0]["algorithm"] != findings[0]["signature_algorithm"]


def test_subject_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert "ECDAT Test Certificate" in findings[0]["subject"]


def test_issuer_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert "ECDAT Test Org" in findings[0]["issuer"]


def test_validity_dates_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["not_before"]
    assert findings[0]["not_after"]
    assert "GMT" in findings[0]["not_before"]


def test_serial_number_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["serial_number"]


def test_certificate_version_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["certificate_version"] == 3


def test_subject_alternative_names_extracted():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    sans = findings[0].get("subject_alternative_names")
    assert sans is not None
    assert any("localhost" in s for s in sans)


# --------------------------------------------------------------------------- #
# EC / Ed25519 certificates
# --------------------------------------------------------------------------- #


def test_ec_certificate_algorithm_and_curve():
    findings = scan_certificate(_sample("ec_p256_cert.pem"))
    assert findings[0]["algorithm"] == "EC"
    assert findings[0]["key_size"] == 256
    assert findings[0]["ec_curve"] == "prime256v1"
    assert "ecdsa" in findings[0]["signature_algorithm"].lower()


def test_ed25519_certificate_algorithm():
    findings = scan_certificate(_sample("ed25519_cert.pem"))
    assert findings[0]["algorithm"] == "Ed25519"


# --------------------------------------------------------------------------- #
# DER format
# --------------------------------------------------------------------------- #


def test_der_certificate_is_detected():
    findings = scan_certificate(_sample("rsa2048_cert.der"))
    assert len(findings) == 1
    assert findings[0]["source_format"] == "DER"
    assert findings[0]["algorithm"] == "RSA"
    assert findings[0]["key_size"] == 2048


# --------------------------------------------------------------------------- #
# PKCS#12
# --------------------------------------------------------------------------- #


def test_pkcs12_without_password_is_inspected():
    findings = scan_certificate(_sample("no_password.p12"))
    assert len(findings) == 1
    assert findings[0]["artifact_type"] == "certificate"
    assert findings[0]["source_format"] == "PKCS12"
    assert findings[0]["algorithm"] == "RSA"


def test_pkcs12_with_password_but_none_supplied_reports_password_protected():
    findings = scan_certificate(_sample("with_password.pfx"))
    assert len(findings) == 1
    assert findings[0]["artifact_type"] == "pkcs12"
    assert findings[0]["password_protected"] is True
    # must not have leaked any metadata it couldn't actually extract
    assert "subject" not in findings[0]
    assert "algorithm" not in findings[0]


def test_pkcs12_with_correct_password_is_inspected():
    findings = scan_certificate(_sample("with_password.pfx"), password="testpass123")
    assert len(findings) == 1
    assert findings[0]["artifact_type"] == "certificate"
    assert findings[0]["algorithm"] == "RSA"
    assert findings[0]["key_size"] == 4096


def test_pkcs12_wrong_password_reports_password_protected_not_crash():
    findings = scan_certificate(_sample("with_password.pfx"), password="wrong-password")
    assert findings[0]["artifact_type"] == "pkcs12"
    assert findings[0]["password_protected"] is True


# --------------------------------------------------------------------------- #
# Not-actually-a-certificate PEM content
# --------------------------------------------------------------------------- #


def test_private_key_only_pem_is_not_classified_as_certificate():
    findings = scan_certificate(_sample("private_key_only.pem"))
    assert findings == []


def test_csr_only_pem_is_not_classified_as_certificate():
    findings = scan_certificate(_sample("csr_only.pem"))
    assert findings == []


# --------------------------------------------------------------------------- #
# Security: no private key / secret material ever exposed
# --------------------------------------------------------------------------- #


def test_no_private_key_material_in_output_for_valid_cert():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    serialized = str(findings)
    assert "BEGIN RSA PRIVATE KEY" not in serialized
    assert "BEGIN PRIVATE KEY" not in serialized


def test_no_private_key_material_in_output_for_pkcs12():
    findings = scan_certificate(_sample("no_password.p12"))
    serialized = str(findings)
    assert "BEGIN RSA PRIVATE KEY" not in serialized
    assert "BEGIN PRIVATE KEY" not in serialized
    assert "BEGIN ENCRYPTED PRIVATE KEY" not in serialized


def test_no_password_leaked_in_password_protected_finding():
    findings = scan_certificate(_sample("with_password.pfx"))
    serialized = str(findings)
    assert "testpass123" not in serialized


def test_error_messages_do_not_leak_private_key_material(monkeypatch):
    import scanner.detectors.certificate_detector as cd

    def fake_run(args, input_bytes=None, timeout=cd.OPENSSL_TIMEOUT_SECONDS):
        class FakeResult:
            returncode = 1
            stdout = b""
            stderr = (
                b"error parsing\n"
                b"-----BEGIN RSA PRIVATE KEY-----\n"
                b"MIIEpAIBAAKCAQEAtestFAKEnotarealkey\n"
                b"-----END RSA PRIVATE KEY-----\n"
            )
        return FakeResult()

    monkeypatch.setattr(cd, "_run_openssl", fake_run)

    with pytest.raises(CertificateDetectorError) as excinfo:
        scan_certificate(_sample("rsa2048_cert.pem"))
    assert "BEGIN RSA PRIVATE KEY" not in str(excinfo.value)
    assert "MIIEpAIBAAKCAQEA" not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# File path propagation / detection method / confidence
# --------------------------------------------------------------------------- #


def test_file_path_propagation():
    path = _sample("rsa2048_cert.pem")
    findings = scan_certificate(path)
    assert findings[0]["file_path"] == path


def test_detection_method_is_openssl():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["detection_method"] == "openssl"


def test_confidence_is_high_for_successfully_parsed_certificate():
    findings = scan_certificate(_sample("rsa2048_cert.pem"))
    assert findings[0]["confidence"] >= 0.95


def test_confidence_is_lower_for_password_protected_pkcs12():
    findings = scan_certificate(_sample("with_password.pfx"))
    assert findings[0]["confidence"] < 0.95


# --------------------------------------------------------------------------- #
# scan_certificate_content convenience wrapper
# --------------------------------------------------------------------------- #


def test_scan_certificate_content_matches_scan_certificate():
    content = _read("rsa2048_cert.pem")
    findings = scan_certificate_content(content, file_path="in-memory-cert.pem", suffix=".pem")
    assert len(findings) == 1
    assert findings[0]["algorithm"] == "RSA"
    assert findings[0]["key_size"] == 2048
    assert findings[0]["file_path"] == "in-memory-cert.pem"


def test_scan_certificate_content_unsupported_suffix_raises():
    with pytest.raises(CertificateDetectorError):
        scan_certificate_content(b"irrelevant", suffix=".txt")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
