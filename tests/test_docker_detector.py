"""
test_docker_detector.py
========================

Standalone pytest test suite for docker_detector.py.

This file is self-contained and does not import anything from an existing
scanner project. It expects `docker_detector.py` to be importable (same
directory, or on PYTHONPATH), and expects the sample Dockerfiles listed in
SAMPLES_DIR (see below) to be present alongside it.

Run with:
    pytest test_docker_detector.py -v
"""

import os

import pytest

from scanner.detectors.docker_detector import (
    DockerDetectorError,
    scan_dockerfile,
    scan_dockerfile_content,
)

SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "samples",
    "docker",
)


def _sample_path(name: str) -> str:
    return os.path.join(SAMPLES_DIR, name)


def _findings_of_type(findings, artifact_type):
    return [f for f in findings if f["artifact_type"] == artifact_type]


def _algorithms(findings):
    return {f["algorithm"] for f in findings if f.get("algorithm")}


def _libraries(findings):
    return {f["library"] for f in findings if f.get("library")}


# --------------------------------------------------------------------------- #
# Basic parsing behavior
# --------------------------------------------------------------------------- #


def test_scan_dockerfile_missing_file_raises():
    with pytest.raises(DockerDetectorError):
        scan_dockerfile("/nonexistent/path/Dockerfile")


def test_line_numbers_are_correct():
    content = (
        "FROM python:3.12\n"  # line 1
        "\n"  # line 2 (blank)
        "RUN apt-get install -y openssl\n"  # line 3
        "\n"
        "RUN openssl genrsa -out server.key 2048\n"  # line 5
    )
    findings = scan_dockerfile_content(content)
    line_numbers = sorted(f["line_number"] for f in findings)

    assert 3 in line_numbers
    assert 5 in line_numbers


def test_docker_instruction_is_preserved():
    content = "RUN apt-get install -y openssl\n"
    findings = scan_dockerfile_content(content)

    assert len(findings) == 1
    assert findings[0]["docker_instruction"] == "RUN"


def test_file_path_is_propagated():
    content = "RUN apt-get install -y openssl\n"
    findings = scan_dockerfile_content(
        content,
        file_path="my/custom/Dockerfile",
    )

    assert findings[0]["file_path"] == "my/custom/Dockerfile"


def test_line_continuation_is_joined_and_still_detected():
    content = (
        "RUN apt-get update && \\\n"
        "    apt-get install -y \\\n"
        "    openssl\n"
    )
    findings = scan_dockerfile_content(content)
    libs = _libraries(findings)

    assert "OpenSSL" in libs


# --------------------------------------------------------------------------- #
# OpenSSL: install vs. use
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "cmd",
    [
        "RUN apt-get install -y openssl",
        "RUN apt install openssl",
        "RUN apk add openssl",
        "RUN yum install openssl",
        "RUN dnf install openssl",
    ],
)
def test_openssl_installation_detected(cmd):
    findings = scan_dockerfile_content(cmd + "\n")
    lib_findings = _findings_of_type(findings, "library")

    assert any(f["library"] == "OpenSSL" for f in lib_findings)

    # Installing OpenSSL must not itself claim a specific algorithm was used.
    assert not any(
        f["artifact_type"] == "algorithm"
        for f in findings
    )


def test_openssl_install_is_not_confused_with_usage():
    content = "RUN apt-get install -y openssl\n"
    findings = scan_dockerfile_content(content)

    assert all(
        f["artifact_type"] != "algorithm"
        for f in findings
    )
    assert findings[0]["evidence_type"] == "package_install"


@pytest.mark.parametrize(
    "cmd,expected_subcmd_evidence",
    [
        (
            "RUN openssl genrsa -out server.key 2048",
            "algorithm",
        ),
        (
            "RUN openssl req -new -x509 -key server.key -out server.crt",
            "certificate_generation",
        ),
        (
            "RUN openssl s_client -connect example.com:443",
            "protocol",
        ),
    ],
)
def test_openssl_commands_detected(cmd, expected_subcmd_evidence):
    findings = scan_dockerfile_content(cmd)

    assert any(
        f["artifact_type"] == expected_subcmd_evidence
        for f in findings
    )


def test_openssl_x509_inspection_is_not_certificate_generation():
    findings = scan_dockerfile_content(
        "RUN openssl x509 -in server.crt -text\n"
    )

    assert not any(
        f["artifact_type"] == "certificate_generation"
        for f in findings
    )


def test_openssl_genrsa_extracts_algorithm_and_keysize():
    content = "RUN openssl genrsa -out server.key 2048\n"
    findings = scan_dockerfile_content(content)
    algo_findings = _findings_of_type(findings, "algorithm")

    assert any(
        f["algorithm"] == "RSA" and f["key_size"] == 2048
        for f in algo_findings
    )


def test_openssl_genrsa_does_not_invent_keysize_when_absent():
    content = "RUN openssl genrsa -out server.key\n"
    findings = scan_dockerfile_content(content)
    algo_findings = _findings_of_type(findings, "algorithm")

    assert len(algo_findings) == 1
    assert algo_findings[0]["algorithm"] == "RSA"
    assert algo_findings[0]["key_size"] is None


def test_openssl_newkey_rsa_extracts_keysize():
    content = (
        "RUN openssl req -x509 -newkey rsa:4096 "
        "-keyout key.pem -out cert.pem\n"
    )
    findings = scan_dockerfile_content(content)
    algo_findings = _findings_of_type(findings, "algorithm")

    assert any(
        f["algorithm"] == "RSA" and f["key_size"] == 4096
        for f in algo_findings
    )


# --------------------------------------------------------------------------- #
# Generic algorithm detection
# --------------------------------------------------------------------------- #


def test_ecc_and_ec_patterns_detected():
    content = "RUN echo building with ECDSA and ECDH support\n"
    findings = scan_dockerfile_content(content)
    algos = _algorithms(findings)

    assert "ECDSA" in algos
    assert "ECDH" in algos


def test_ec_openssl_subcommand_detected():
    content = (
        "RUN openssl ecparam -name prime256v1 "
        "-genkey -out ec.key\n"
    )
    findings = scan_dockerfile_content(content)
    algo_findings = _findings_of_type(findings, "algorithm")

    assert any(
        f["algorithm"] and f["algorithm"].startswith("EC")
        for f in algo_findings
    )


def test_aes_patterns_detected():
    content = "ENV CIPHER_SUITE=AES-256-GCM\n"
    findings = scan_dockerfile_content(content)
    algos = _algorithms(findings)

    assert any(a.startswith("AES") for a in algos)


def test_sha_patterns_detected():
    content = "RUN openssl dgst -sha256 -sign key.pem file.txt\n"
    findings = scan_dockerfile_content(content)
    algos = _algorithms(findings)

    assert "SHA-256" in algos


def test_ed25519_and_chacha_detected():
    content = (
        "RUN echo ChaCha20-Poly1305 and Ed25519 are supported\n"
    )
    findings = scan_dockerfile_content(content)
    algos = _algorithms(findings)

    assert "ChaCha20-Poly1305" in algos
    assert "Ed25519" in algos


# --------------------------------------------------------------------------- #
# Crypto libraries / packages
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "cmd,expected_lib",
    [
        ("RUN pip install cryptography", "cryptography (Python)"),
        ("RUN pip install pycryptodome", "PyCryptodome"),
        ("RUN pip install pyOpenSSL", "pyOpenSSL"),
        ("RUN npm install node-forge", "node-forge"),
        ("RUN apt-get install libssl-dev", "OpenSSL (dev headers)"),
    ],
)
def test_crypto_library_detection(cmd, expected_lib):
    findings = scan_dockerfile_content(cmd + "\n")
    libs = _libraries(findings)

    assert expected_lib in libs


def test_library_install_is_dependency_not_usage_claim():
    content = "RUN pip install cryptography\n"
    findings = scan_dockerfile_content(content)

    assert all(
        f["artifact_type"] == "library"
        for f in findings
    )
    assert all(
        f["artifact_type"] != "algorithm"
        for f in findings
    )


# --------------------------------------------------------------------------- #
# TLS / SSL / protocol
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value,expected_version",
    [
        ("TLSv1.2", "TLSv1.2"),
        ("TLSv1.3", "TLSv1.3"),
    ],
)
def test_tls_versions_detected(value, expected_version):
    content = f"ENV TLS_VERSION={value}\n"
    findings = scan_dockerfile_content(content)
    protocol_findings = _findings_of_type(findings, "protocol")

    assert any(
        f["protocol_version"] == expected_version
        for f in protocol_findings
    )


def test_tls_flag_in_openssl_command_detected():
    content = (
        "RUN openssl s_client -connect example.com:443 "
        "-tls1_2\n"
    )
    findings = scan_dockerfile_content(content)
    protocol_findings = _findings_of_type(findings, "protocol")

    assert any(
        f["protocol_version"] == "TLSv1.2"
        for f in protocol_findings
    )


# --------------------------------------------------------------------------- #
# Certificates and keys
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "ext",
    ["crt", "cer", "pem", "der", "p12", "pfx"],
)
def test_certificate_extensions_detected(ext):
    content = f"COPY server.{ext} /etc/ssl/certs/\n"
    findings = scan_dockerfile_content(content)

    assert any(
        f["artifact_type"] == "certificate_reference"
        for f in findings
    )


def test_key_extension_detected():
    content = "COPY server.key /etc/ssl/private/\n"
    findings = scan_dockerfile_content(content)

    assert any(
        f["artifact_type"] == "key_reference"
        for f in findings
    )


def test_certificate_and_key_env_vars_detected():
    content = (
        "ENV SSL_CERT=/etc/ssl/server.crt\n"
        "ENV SSL_KEY=/etc/ssl/server.key\n"
    )
    findings = scan_dockerfile_content(content)

    assert any(
        f["artifact_type"] == "certificate_reference"
        for f in findings
    )
    assert any(
        f["artifact_type"] == "key_reference"
        for f in findings
    )


def test_no_secret_key_material_is_exposed():
    content = (
        'ENV PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY----- '
        "MIIEpAIBAAKCAQEAtestFAKEnotarealkey "
        '-----END RSA PRIVATE KEY-----"\n'
    )
    findings = scan_dockerfile_content(content)

    for f in findings:
        assert "BEGIN RSA PRIVATE KEY" not in f["code_snippet"]
        assert "MIIEpAIBAAKCAQEA" not in f["code_snippet"]


# --------------------------------------------------------------------------- #
# False-positive control
# --------------------------------------------------------------------------- #


def test_comments_do_not_create_false_positives():
    content = "# TODO: migrate RSA to PQC\n"
    findings = scan_dockerfile_content(content)

    assert findings == []


def test_ordinary_instructions_do_not_create_crypto_findings():
    content = (
        "FROM python:3.12\n"
        "WORKDIR /app\n"
        "COPY requirements.txt .\n"
        "RUN pip install -r requirements.txt\n"
        "COPY . .\n"
        'CMD ["python", "app.py"]\n'
    )
    findings = scan_dockerfile_content(content)

    assert findings == []


def test_substring_matches_do_not_create_false_positives():
    content = (
        "FROM python:3.12\n"
        "RUN mkdir -p /app/my_ssl_folder\n"
        "COPY classification.txt /app/\n"
        "ENV APP_PASSWORD_HINT=none\n"
    )
    findings = scan_dockerfile_content(content)

    assert findings == []


# --------------------------------------------------------------------------- #
# End-to-end sample Dockerfile tests
# --------------------------------------------------------------------------- #


def test_sample_dockerfile_crypto():
    findings = scan_dockerfile(
        _sample_path("Dockerfile_crypto")
    )

    libs = _libraries(findings)

    assert "OpenSSL" in libs
    assert "cryptography (Python)" in libs

    algos = _algorithms(findings)

    assert "RSA" in algos

    rsa_findings = [
        f for f in findings
        if f.get("algorithm") == "RSA"
    ]

    assert any(
        f["key_size"] == 2048
        for f in rsa_findings
    )

    protocol_findings = _findings_of_type(
        findings,
        "protocol",
    )

    assert any(
        f["protocol_version"] == "TLSv1.2"
        for f in protocol_findings
    )

    assert any(
        f["artifact_type"] == "certificate_generation"
        for f in findings
    )

    assert any(
        f["artifact_type"] == "key_reference"
        for f in findings
    )


def test_sample_dockerfile_library_only_has_no_algorithm_findings():
    findings = scan_dockerfile(
        _sample_path("Dockerfile_library_only")
    )

    assert len(findings) > 0

    assert all(
        f["artifact_type"] == "library"
        for f in findings
    )

    assert all(
        f["artifact_type"] != "algorithm"
        for f in findings
    )


def test_sample_dockerfile_normal_has_no_findings():
    findings = scan_dockerfile(
        _sample_path("Dockerfile_normal")
    )

    assert findings == []


def test_sample_dockerfile_tls_detects_tls_and_certs_and_keys():
    findings = scan_dockerfile(
        _sample_path("Dockerfile_tls")
    )

    protocol_findings = _findings_of_type(
        findings,
        "protocol",
    )

    assert any(
        f["protocol_version"] == "TLSv1.3"
        for f in protocol_findings
    )

    assert any(
        f["artifact_type"] == "certificate_reference"
        for f in findings
    )

    assert any(
        f["artifact_type"] == "key_reference"
        for f in findings
    )

    # The comment line must not have produced an RSA finding.
    assert "RSA" not in _algorithms(findings)


def test_sample_dockerfile_certificate():
    findings = scan_dockerfile(
        _sample_path("Dockerfile_certificate")
    )

    assert any(
        f["library"] == "OpenSSL"
        for f in findings
        if f.get("library")
    )

    algos = _algorithms(findings)

    assert "RSA" in algos

    rsa_findings = [
        f for f in findings
        if f.get("algorithm") == "RSA"
    ]

    assert any(
        f["key_size"] == 4096
        for f in rsa_findings
    )

    assert any(
        f["artifact_type"] == "certificate_generation"
        for f in findings
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))