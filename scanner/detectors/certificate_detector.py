
"""
certificate_detector.py
=======================

Standalone X.509 certificate / PKCS#12 detector for ECDAT.

This module inspects actual certificate files on disk and extracts
certificate metadata using the OpenSSL CLI.

Supported:
    - PEM (.pem, .crt, .cer)
    - DER (.der)
    - PKCS#12 (.p12, .pfx)

The detector never extracts or returns private-key material.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class CertificateDetectorError(Exception):
    """Raised for unrecoverable certificate inspection errors."""


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

OPENSSL_TIMEOUT_SECONDS = 10

SUPPORTED_EXTENSIONS = {
    ".pem",
    ".crt",
    ".cer",
    ".der",
    ".p12",
    ".pfx",
}

X509_EXTENSIONS = {
    ".pem",
    ".crt",
    ".cer",
    ".der",
}

PKCS12_EXTENSIONS = {
    ".p12",
    ".pfx",
}

_OPENSSL_BIN = "openssl"


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #

@dataclass
class CertificateFinding:
    artifact_type: str
    file_path: str

    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None

    not_before: Optional[str] = None
    not_after: Optional[str] = None

    # Public-key algorithm
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    ec_curve: Optional[str] = None

    signature_algorithm: Optional[str] = None
    certificate_version: Optional[int] = None

    subject_alternative_names: Optional[List[str]] = None
    key_usage: Optional[List[str]] = None
    extended_key_usage: Optional[List[str]] = None

    source_format: Optional[str] = None
    password_protected: Optional[bool] = None
    note: Optional[str] = None

    detection_method: str = "openssl"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the dataclass to a dictionary while removing fields
        that were not populated.
        """
        data = asdict(self)

        return {
            key: value
            for key, value in data.items()
            if value is not None
        }


# --------------------------------------------------------------------------- #
# Secret scrubbing
# --------------------------------------------------------------------------- #

_PEM_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN\s+"
    r"(?:RSA|EC|DSA|ENCRYPTED|OPENSSH)?\s*PRIVATE KEY"
    r"-----.*?"
    r"-----END\s+"
    r"(?:RSA|EC|DSA|ENCRYPTED|OPENSSH)?\s*PRIVATE KEY"
    r"-----",
    re.IGNORECASE | re.DOTALL,
)


def _scrub(text: str) -> str:
    """
    Remove private-key PEM blocks from text before storing or displaying it.
    """
    if not text:
        return text

    return _PEM_KEY_BLOCK_RE.sub(
        "<redacted: private key material>",
        text,
    )


def _truncate(text: str, limit: int = 500) -> str:
    """
    Limit error messages to a reasonable size.
    """
    text = text.strip()

    if len(text) > limit:
        return text[:limit] + " ...(truncated)"

    return text


# --------------------------------------------------------------------------- #
# OpenSSL plumbing
# --------------------------------------------------------------------------- #

_openssl_checked = False
_openssl_available = False


def _ensure_openssl_available() -> None:
    """
    Verify that OpenSSL exists and can be executed.
    """

    global _openssl_checked
    global _openssl_available

    if _openssl_checked and _openssl_available:
        return

    if shutil.which(_OPENSSL_BIN) is None:
        _openssl_checked = True
        _openssl_available = False

        raise CertificateDetectorError(
            "OpenSSL CLI was not found on PATH. "
            "Install OpenSSL and ensure the 'openssl' command is available."
        )

    try:
        process = subprocess.run(
            [_OPENSSL_BIN, "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=OPENSSL_TIMEOUT_SECONDS,
            shell=False,
        )

    except (OSError, subprocess.TimeoutExpired) as exc:
        _openssl_checked = True
        _openssl_available = False

        raise CertificateDetectorError(
            f"Could not run 'openssl version': {exc}"
        ) from exc

    if process.returncode != 0:
        _openssl_checked = True
        _openssl_available = False

        error = _scrub(
            _truncate(
                process.stderr.decode(
                    "utf-8",
                    "replace",
                )
            )
        )

        raise CertificateDetectorError(
            f"'openssl version' failed with code "
            f"{process.returncode}: {error}"
        )

    _openssl_checked = True
    _openssl_available = True


def _run_openssl(
    args: List[str],
    input_bytes: Optional[bytes] = None,
    timeout: int = OPENSSL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess:
    """
    Safely execute OpenSSL.

    Important:
        - shell=False
        - argument list instead of shell command
        - timeout
        - stdout/stderr captured
    """

    command = [_OPENSSL_BIN] + args

    try:
        return subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )

    except subprocess.TimeoutExpired as exc:
        raise CertificateDetectorError(
            f"OpenSSL command timed out after {timeout}s: "
            f"{' '.join(args[:2])}..."
        ) from exc

    except OSError as exc:
        raise CertificateDetectorError(
            f"Failed to execute OpenSSL: {exc}"
        ) from exc


# --------------------------------------------------------------------------- #
# OpenSSL x509 text parsing
# --------------------------------------------------------------------------- #

_SIG_ALG_RE = re.compile(
    r"Signature Algorithm:\s*(\S+)",
    re.IGNORECASE,
)

_PUBKEY_ALG_RE = re.compile(
    r"Public Key Algorithm:\s*(\S+)",
    re.IGNORECASE,
)

_RSA_KEYSIZE_RE = re.compile(
    r"RSA Public-Key:\s*\((\d+)\s*bit\)",
    re.IGNORECASE,
)

_GENERIC_KEYSIZE_RE = re.compile(
    r"Public-Key:\s*\((\d+)\s*bit\)",
    re.IGNORECASE,
)

_EC_CURVE_RE = re.compile(
    r"(?:ASN1 OID|NIST CURVE):\s*(\S+)",
    re.IGNORECASE,
)

_VERSION_RE = re.compile(
    r"Version:\s*(\d+)",
    re.IGNORECASE,
)

_SAN_BLOCK_RE = re.compile(
    r"X509v3 Subject Alternative Name:\s*(?:critical\s*)?\n"
    r"\s*(.+)",
    re.IGNORECASE,
)

_KEY_USAGE_BLOCK_RE = re.compile(
    r"X509v3 Key Usage:\s*(?:critical\s*)?\n"
    r"\s*(.+)",
    re.IGNORECASE,
)

_EXT_KEY_USAGE_BLOCK_RE = re.compile(
    r"X509v3 Extended Key Usage:\s*(?:critical\s*)?\n"
    r"\s*(.+)",
    re.IGNORECASE,
)


# OpenSSL can expose different names for the same public-key type.
_PUBKEY_ALG_CANON = {
    "rsaencryption": "RSA",
    "rsassapss": "RSA",
    "id-ecpublickey": "EC",
    "id-ecpublickey": "EC",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "id-dsa": "DSA",
    "dsaencryption": "DSA",
}


def _canonical_pubkey_algorithm(raw: str) -> str:
    """
    Convert OpenSSL's public-key algorithm name to a simpler
    ECDAT-friendly name.
    """

    value = raw.strip()

    return _PUBKEY_ALG_CANON.get(
        value.lower(),
        value,
    )


def _parse_x509_text(text_output: str) -> Dict[str, Any]:
    """
    Parse relevant metadata from:

        openssl x509 -noout -text
    """

    fields: Dict[str, Any] = {}

    # Signature algorithm
    match = _SIG_ALG_RE.search(text_output)

    if match:
        fields["signature_algorithm"] = match.group(1)

    # Public-key algorithm
    match = _PUBKEY_ALG_RE.search(text_output)

    if match:
        fields["algorithm"] = _canonical_pubkey_algorithm(
            match.group(1)
        )

    # RSA key size
    match = _RSA_KEYSIZE_RE.search(text_output)

    if match:
        fields["key_size"] = int(match.group(1))

    else:
        # Generic key size
        match = _GENERIC_KEYSIZE_RE.search(text_output)

        if match:
            fields["key_size"] = int(match.group(1))

    # EC curve
    match = _EC_CURVE_RE.search(text_output)

    if match:
        fields["ec_curve"] = match.group(1)

    # Certificate version
    match = _VERSION_RE.search(text_output)

    if match:
        fields["certificate_version"] = int(match.group(1))

    # Subject Alternative Names
    match = _SAN_BLOCK_RE.search(text_output)

    if match:
        sans = [
            item.strip()
            for item in match.group(1).split(",")
            if item.strip()
        ]

        if sans:
            fields["subject_alternative_names"] = sans

    # Key Usage
    match = _KEY_USAGE_BLOCK_RE.search(text_output)

    if match:
        usages = [
            item.strip()
            for item in match.group(1).split(",")
            if item.strip()
        ]

        if usages:
            fields["key_usage"] = usages

    # Extended Key Usage
    match = _EXT_KEY_USAGE_BLOCK_RE.search(text_output)

    if match:
        usages = [
            item.strip()
            for item in match.group(1).split(",")
            if item.strip()
        ]

        if usages:
            fields["extended_key_usage"] = usages

    return fields


def _parse_subject_issuer_dates(
    metadata_output: str,
) -> Dict[str, Any]:
    """
    Parse:

        openssl x509 -noout
        -subject
        -issuer
        -serial
        -startdate
        -enddate
    """

    fields: Dict[str, Any] = {}

    for line in metadata_output.splitlines():

        line = line.strip()

        if not line or "=" not in line:
            continue

        key, _, value = line.partition("=")

        key = key.strip().lower()
        value = value.strip()

        if key == "subject":
            fields["subject"] = value

        elif key == "issuer":
            fields["issuer"] = value

        elif key == "serial":
            fields["serial_number"] = value

        elif key == "notbefore":
            fields["not_before"] = value

        elif key == "notafter":
            fields["not_after"] = value

    return fields


# --------------------------------------------------------------------------- #
# PEM object detection
# --------------------------------------------------------------------------- #

_PRIVATE_KEY_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
)

_PUBLIC_KEY_MARKERS = (
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN RSA PUBLIC KEY-----",
)

_CSR_MARKERS = (
    "-----BEGIN CERTIFICATE REQUEST-----",
    "-----BEGIN NEW CERTIFICATE REQUEST-----",
)

_CERT_MARKERS = (
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN TRUSTED CERTIFICATE-----",
)


def _sniff_pem_object_type(
    file_path: str,
) -> Optional[str]:
    """
    Best-effort identification of a PEM object.

    This is NOT used as the authoritative certificate detector.
    OpenSSL remains authoritative.
    """

    try:
        with open(file_path, "rb") as file:
            head = file.read(8192)

    except OSError:
        return None

    text = head.decode(
        "utf-8",
        errors="ignore",
    )

    if any(marker in text for marker in _PRIVATE_KEY_MARKERS):
        return "private_key"

    if any(marker in text for marker in _CSR_MARKERS):
        return "certificate_signing_request"

    if any(marker in text for marker in _PUBLIC_KEY_MARKERS):
        return "public_key"

    if any(marker in text for marker in _CERT_MARKERS):
        return "certificate"

    return None


# --------------------------------------------------------------------------- #
# X.509 handling
# --------------------------------------------------------------------------- #

def _try_x509_parse(
    file_path: str,
    inform: str,
    timeout: int,
) -> subprocess.CompletedProcess:

    return _run_openssl(
        [
            "x509",
            "-in",
            file_path,
            "-inform",
            inform,
            "-noout",
            "-text",
        ],
        timeout=timeout,
    )


def _scan_x509_file(
    file_path: str,
    timeout: int,
) -> List[Dict[str, Any]]:

    # First try PEM.
    pem_result = _try_x509_parse(
        file_path,
        "PEM",
        timeout,
    )

    source_format = "PEM"
    result = pem_result

    # If PEM failed, try DER.
    if result.returncode != 0:

        der_result = _try_x509_parse(
            file_path,
            "DER",
            timeout,
        )

        if der_result.returncode == 0:
            result = der_result
            source_format = "DER"

    # Neither PEM nor DER worked.
    if result.returncode != 0:

        pem_kind = _sniff_pem_object_type(
            file_path
        )

        # These are valid PEM objects but NOT certificates.
        if pem_kind in (
            "private_key",
            "certificate_signing_request",
            "public_key",
        ):
            return []

        # Otherwise the file is genuinely malformed.
        stderr_text = _scrub(
            _truncate(
                pem_result.stderr.decode(
                    "utf-8",
                    "replace",
                )
            )
        )

        raise CertificateDetectorError(
            f"OpenSSL could not parse '{file_path}' "
            f"as a PEM or DER X.509 certificate: "
            f"{stderr_text}"
        )

    # Parse detailed certificate information.
    text_output = result.stdout.decode(
        "utf-8",
        "replace",
    )

    x509_fields = _parse_x509_text(
        text_output
    )

    # Get subject / issuer / dates / serial.
    meta_result = _run_openssl(
        [
            "x509",
            "-in",
            file_path,
            "-inform",
            source_format,
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-startdate",
            "-enddate",
        ],
        timeout=timeout,
    )

    meta_fields: Dict[str, Any] = {}

    if meta_result.returncode == 0:

        meta_fields = _parse_subject_issuer_dates(
            meta_result.stdout.decode(
                "utf-8",
                "replace",
            )
        )

    finding = CertificateFinding(
        artifact_type="certificate",
        file_path=file_path,
        source_format=source_format,
        detection_method="openssl",
        confidence=1.0,

        # IMPORTANT:
        # This remains ec_curve.
        # Do NOT change this to "curve" unless your Artifact model
        # explicitly contains a field called curve.
        **x509_fields,

        **meta_fields,
    )

    return [finding.to_dict()]


# --------------------------------------------------------------------------- #
# Certificate bytes through stdin
# --------------------------------------------------------------------------- #

def _scan_x509_bytes_via_stdin(
    content: bytes,
    display_path: str,
    timeout: int,
) -> List[Dict[str, Any]]:

    result = _run_openssl(
        [
            "x509",
            "-inform",
            "PEM",
            "-noout",
            "-text",
        ],
        input_bytes=content,
        timeout=timeout,
    )

    if result.returncode != 0:

        stderr_text = _scrub(
            _truncate(
                result.stderr.decode(
                    "utf-8",
                    "replace",
                )
            )
        )

        raise CertificateDetectorError(
            f"OpenSSL could not parse the certificate "
            f"extracted from '{display_path}': "
            f"{stderr_text}"
        )

    text_output = result.stdout.decode(
        "utf-8",
        "replace",
    )

    x509_fields = _parse_x509_text(
        text_output
    )

    meta_result = _run_openssl(
        [
            "x509",
            "-inform",
            "PEM",
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-startdate",
            "-enddate",
        ],
        input_bytes=content,
        timeout=timeout,
    )

    meta_fields: Dict[str, Any] = {}

    if meta_result.returncode == 0:

        meta_fields = _parse_subject_issuer_dates(
            meta_result.stdout.decode(
                "utf-8",
                "replace",
            )
        )

    finding = CertificateFinding(
        artifact_type="certificate",
        file_path=display_path,
        source_format="PKCS12",
        detection_method="openssl",
        confidence=1.0,

        **x509_fields,
        **meta_fields,
    )

    return [finding.to_dict()]


# --------------------------------------------------------------------------- #
# PKCS#12 handling
# --------------------------------------------------------------------------- #

_PKCS12_PASSWORD_ERROR_MARKERS = (
    "mac verify error",
    "invalid password",
    "wrong pass phrase",
    "unable to load pkcs12",
    "bad decrypt",
)


def _scan_pkcs12_file(
    file_path: str,
    password: Optional[str],
    timeout: int,
) -> List[Dict[str, Any]]:

    # Empty password is intentionally used only when no password
    # was supplied. We never guess passwords.
    passin = (
        password
        if password is not None
        else ""
    )

    args = [
        "pkcs12",
        "-in",
        file_path,
        "-nokeys",
        "-clcerts",
        "-passin",
        f"pass:{passin}",
    ]

    result = _run_openssl(
        args,
        timeout=timeout,
    )

    if result.returncode != 0:

        stderr_text_raw = result.stderr.decode(
            "utf-8",
            "replace",
        )

        stderr_lower = stderr_text_raw.lower()

        if any(
            marker in stderr_lower
            for marker in _PKCS12_PASSWORD_ERROR_MARKERS
        ):

            return [
                CertificateFinding(
                    artifact_type="pkcs12",
                    file_path=file_path,
                    source_format="PKCS12",
                    password_protected=True,
                    note=(
                        "PKCS#12 container requires a password; "
                        "metadata was not extracted."
                    ),
                    detection_method="openssl",
                    confidence=0.5,
                ).to_dict()
            ]

        stderr_text = _scrub(
            _truncate(stderr_text_raw)
        )

        raise CertificateDetectorError(
            f"OpenSSL failed to read PKCS#12 container "
            f"'{file_path}': {stderr_text}"
        )

    # -nokeys ensures private keys are not emitted.
    pem_text = result.stdout

    if b"BEGIN CERTIFICATE" not in pem_text:
        return []

    return _scan_x509_bytes_via_stdin(
        pem_text,
        file_path,
        timeout,
    )


# --------------------------------------------------------------------------- #
# Public interface
# --------------------------------------------------------------------------- #

def scan_certificate(
    file_path: str,
    password: Optional[str] = None,
    timeout: int = OPENSSL_TIMEOUT_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Scan one certificate / PKCS#12 file.

    Supported extensions:
        .pem
        .crt
        .cer
        .der
        .p12
        .pfx
    """

    if not os.path.exists(file_path):
        raise CertificateDetectorError(
            f"Certificate file not found: {file_path}"
        )

    if not os.path.isfile(file_path):
        raise CertificateDetectorError(
            f"Not a regular file: {file_path}"
        )

    if not os.access(file_path, os.R_OK):
        raise CertificateDetectorError(
            f"Permission denied reading: {file_path}"
        )

    extension = os.path.splitext(
        file_path
    )[1].lower()

    if extension not in SUPPORTED_EXTENSIONS:

        raise CertificateDetectorError(
            f"Unsupported certificate format "
            f"'{extension}' for file: {file_path}. "
            f"Supported extensions: "
            f"{sorted(SUPPORTED_EXTENSIONS)}"
        )

    _ensure_openssl_available()

    if extension in PKCS12_EXTENSIONS:
        return _scan_pkcs12_file(
            file_path,
            password,
            timeout,
        )

    return _scan_x509_file(
        file_path,
        timeout,
    )


def scan_certificate_content(
    content: bytes,
    file_path: str = "certificate",
    suffix: str = ".pem",
    password: Optional[str] = None,
    timeout: int = OPENSSL_TIMEOUT_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Scan certificate bytes already held in memory.
    """

    suffix = suffix.lower()

    if suffix not in SUPPORTED_EXTENSIONS:

        raise CertificateDetectorError(
            f"Unsupported certificate format "
            f"'{suffix}'. Supported extensions: "
            f"{sorted(SUPPORTED_EXTENSIONS)}"
        )

    fd, tmp_path = tempfile.mkstemp(
        suffix=suffix
    )

    try:

        with os.fdopen(fd, "wb") as file:
            file.write(content)

        results = scan_certificate(
            tmp_path,
            password=password,
            timeout=timeout,
        )

        # Replace temporary path with caller-provided path.
        for result in results:
            result["file_path"] = file_path

        return results

    finally:

        try:
            os.remove(tmp_path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

if __name__ == "__main__":

    import json
    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: python certificate_detector.py "
            "<path-to-certificate>"
        )

        raise SystemExit(1)

    try:

        results = scan_certificate(
            sys.argv[1]
        )

    except CertificateDetectorError as exc:

        print(f"Error: {exc}")
        raise SystemExit(1)

    print(
        json.dumps(
            results,
            indent=2,
        )
    )

