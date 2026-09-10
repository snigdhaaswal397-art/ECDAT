"""
docker_detector.py
==================

Standalone Dockerfile cryptography detector.

This module analyzes Dockerfiles for evidence of cryptographic algorithms,
libraries, protocols, certificates, keys, and cryptographic commands.

It intentionally does not:
    - Execute Dockerfiles.
    - Reach into Docker daemons.
    - Pull container images.
    - Parse Python/Java/C/C++ source code.
    - Generate CBOMs.
    - Perform risk scoring.
    - Report findings from comments.
    - Assume that installing a crypto library proves an algorithm is used.
    - Echo private-key material or other embedded secrets.

PUBLIC INTERFACE
----------------

    scan_dockerfile(file_path: str) -> List[Dict[str, Any]]

        Read a Dockerfile from disk and return structured findings.

    scan_dockerfile_content(
        content: str,
        file_path: str = "Dockerfile"
    ) -> List[Dict[str, Any]]

        Analyze Dockerfile content already in memory.

Each finding is returned as a plain dictionary.

IMPORTANT SEMANTICS
-------------------

Actual certificate:
    artifact_type = "certificate"

Static certificate reference:
    artifact_type = "certificate_reference"

Static key reference:
    artifact_type = "key_reference"

Certificate generation command:
    artifact_type = "certificate_generation"

For OpenSSL specifically, certificate generation is reported only when
the command is an actual certificate-generation request such as:

    openssl req -new -x509 ...

Commands such as:

    openssl x509 -in cert.pem -text
    openssl verify cert.pem
    openssl pkcs12 ...
    openssl ca ...

are NOT classified as certificate generation because they inspect, verify,
manage, or operate on certificates rather than necessarily generating one.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DockerDetectorError(Exception):
    """Raised when a Dockerfile cannot be read or is not usable as input."""


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class DockerCryptoFinding:
    """
    A single structured cryptographic finding from a Dockerfile.

    artifact_type may be:
        algorithm
        library
        protocol
        certificate
        certificate_reference
        certificate_generation
        key_reference
    """

    artifact_type: str
    file_path: str
    line_number: int
    code_snippet: str

    docker_instruction: Optional[str] = None

    algorithm: Optional[str] = None
    key_size: Optional[int] = None

    library: Optional[str] = None

    protocol: Optional[str] = None
    protocol_version: Optional[str] = None

    evidence_type: Optional[str] = None
    detection_method: str = "regex/pattern"
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding into the dictionary used by the scanner."""
        result = asdict(self)

        # Match the artifact ID convention used by the rest of the scanner.
        result["artifact_id"] = str(uuid.uuid4())[:8]

        return result


# ---------------------------------------------------------------------------
# Constants / lookup tables
# ---------------------------------------------------------------------------


TARGET_INSTRUCTIONS = {
    "FROM",
    "RUN",
    "CMD",
    "ENTRYPOINT",
    "ENV",
    "ARG",
    "COPY",
    "ADD",
}


INSTRUCTION_RE = re.compile(
    r"^\s*([A-Za-z]+)\s*(.*)$",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Secret / private-key detection
# ---------------------------------------------------------------------------


PEM_HEADER_RE = re.compile(
    r"-----BEGIN\s+"
    r"(?:(?:RSA|EC|DSA|ENCRYPTED|OPENSSH)\s+)?"
    r"PRIVATE KEY"
    r"-----",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Package manager detection
# ---------------------------------------------------------------------------


_PKG_MANAGER_PATTERNS = [
    re.compile(
        r"\bapt-get\s+"
        r"(?:-\S+\s+)*"
        r"install\s+"
        r"(?:-\S+\s+)*"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?<!-get)\bapt\s+"
        r"(?:-\S+\s+)*"
        r"install\s+"
        r"(?:-\S+\s+)*"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bapk\s+"
        r"(?:--\S+\s+)*"
        r"add\s+"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byum\s+"
        r"(?:-\S+\s+)*"
        r"install\s+"
        r"(?:-\S+\s+)*"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdnf\s+"
        r"(?:-\S+\s+)*"
        r"install\s+"
        r"(?:-\S+\s+)*"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bpip3?\s+"
        r"install\s+"
        r"(?:-\S+\s+)*"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bnpm\s+"
        r"install\s+"
        r"(?:-\S+\s+)*"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byarn\s+"
        r"add\s+"
        r"(?:-\S+\s+)*"
        r"(?P<pkgs>[^\n|;&]+)",
        re.IGNORECASE,
    ),
]


KNOWN_CRYPTO_LIBS: Dict[str, Tuple[str, float]] = {
    "openssl": ("OpenSSL", 0.90),
    "libssl-dev": ("OpenSSL (dev headers)", 0.85),
    "libssl1.1": ("OpenSSL", 0.85),
    "libssl3": ("OpenSSL", 0.85),
    "libssl": ("OpenSSL", 0.85),

    "cryptography": ("cryptography (Python)", 0.90),
    "pycryptodome": ("PyCryptodome", 0.90),
    "pycrypto": ("PyCrypto", 0.85),
    "pyopenssl": ("pyOpenSSL", 0.90),

    "crypto": ("crypto (npm)", 0.55),
    "node-forge": ("node-forge", 0.90),
    "forge": ("node-forge", 0.60),

    "bcrypt": ("bcrypt", 0.80),
    "libsodium": ("libsodium", 0.90),
    "sodium-native": ("libsodium (Node bindings)", 0.85),

    "gnutls": ("GnuTLS", 0.85),
    "gnutls-bin": ("GnuTLS", 0.85),

    "mbedtls": ("mbed TLS", 0.85),
    "libmbedtls-dev": ("mbed TLS", 0.85),

    "wolfssl": ("wolfSSL", 0.85),
    "tweetnacl": ("TweetNaCl", 0.80),
}


# ---------------------------------------------------------------------------
# OpenSSL command detection
# ---------------------------------------------------------------------------


OPENSSL_SUBCOMMANDS = (
    "genrsa",
    "genpkey",
    "req",
    "x509",
    "ecparam",
    "ec",
    "dgst",
    "enc",
    "s_client",
    "verify",
    "rsa",
    "pkey",
    "pkcs12",
    "ca",
)


OPENSSL_CMD_RE = re.compile(
    r"\bopenssl\s+("
    + "|".join(OPENSSL_SUBCOMMANDS)
    + r")\b",
    re.IGNORECASE,
)


_KEYGEN_SUBCOMMANDS = {
    "genrsa",
    "genpkey",
}


_EC_SUBCOMMANDS = {
    "ec",
    "ecparam",
}


_COMMON_KEY_SIZES = re.compile(
    r"\b(512|1024|2048|3072|4096|8192|16384)\b"
)


_RSA_KEYGEN_BITS_RE = re.compile(
    r"rsa_keygen_bits\s*:\s*(\d+)",
    re.IGNORECASE,
)


_GENPKEY_ALGO_RE = re.compile(
    r"-algorithm\s+(\S+)",
    re.IGNORECASE,
)


_EC_CURVE_NAME_RE = re.compile(
    r"-(?:name|pkeyopt\s+ec_paramgen_curve)\s*[: ]\s*(\S+)",
    re.IGNORECASE,
)


_DGST_HASH_RE = re.compile(
    r"-(md5|sha1|sha224|sha256|sha384|sha512)\b",
    re.IGNORECASE,
)


_ENC_CIPHER_RE = re.compile(
    r"-((?:aes|des|chacha20)[-\w]*)",
    re.IGNORECASE,
)


_TLS_FLAG_RE = re.compile(
    r"-(tls1_3|tls1_2|tls1_1|tls1|ssl3|ssl2)\b",
    re.IGNORECASE,
)


_NEWKEY_RE = re.compile(
    r"-newkey\s+(rsa|ec|dsa)\s*:\s*(\S+)",
    re.IGNORECASE,
)


_DGST_HASH_CANON = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


_TLS_FLAG_CANON = {
    "tls1_3": "TLSv1.3",
    "tls1_2": "TLSv1.2",
    "tls1_1": "TLSv1.1",
    "tls1": "TLSv1",
    "ssl3": "SSLv3",
    "ssl2": "SSLv2",
}


# ---------------------------------------------------------------------------
# Generic algorithm patterns
# ---------------------------------------------------------------------------


_ALGO_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"\bChaCha20-Poly1305\b", re.IGNORECASE),
        "ChaCha20-Poly1305",
        "symmetric",
    ),
    (
        re.compile(r"\bChaCha20\b", re.IGNORECASE),
        "ChaCha20",
        "symmetric",
    ),
    (
        re.compile(
            r"\bRSA[-_]?(1024|2048|3072|4096|8192)\b",
            re.IGNORECASE,
        ),
        "RSA",
        "public-key",
    ),
    (
        re.compile(r"\bRSA\b", re.IGNORECASE),
        "RSA",
        "public-key",
    ),
    (
        re.compile(r"\bECDSA\b", re.IGNORECASE),
        "ECDSA",
        "public-key",
    ),
    (
        re.compile(r"\bECDH\b", re.IGNORECASE),
        "ECDH",
        "public-key",
    ),
    (
        re.compile(r"\bECC\b", re.IGNORECASE),
        "ECC",
        "public-key",
    ),
    (
        re.compile(r"\bEd25519\b", re.IGNORECASE),
        "Ed25519",
        "public-key",
    ),
    (
        re.compile(r"\bEd448\b", re.IGNORECASE),
        "Ed448",
        "public-key",
    ),
    (
        re.compile(r"\bDSA\b"),
        "DSA",
        "public-key",
    ),
    (
        re.compile(
            r"\bAES"
            r"(?:[-_](128|192|256))?"
            r"(?:[-_](GCM|CBC|CTR|CFB|OFB|ECB))?\b",
            re.IGNORECASE,
        ),
        "AES",
        "symmetric",
    ),
    (
        re.compile(r"\bTriple[-_ ]?DES\b", re.IGNORECASE),
        "3DES",
        "symmetric",
    ),
    (
        re.compile(r"\b3DES\b", re.IGNORECASE),
        "3DES",
        "symmetric",
    ),
    (
        re.compile(r"\bDES\b"),
        "DES",
        "symmetric",
    ),
    (
        re.compile(r"\bSHA[-_]?224\b", re.IGNORECASE),
        "SHA-224",
        "hash",
    ),
    (
        re.compile(r"\bSHA[-_]?256\b", re.IGNORECASE),
        "SHA-256",
        "hash",
    ),
    (
        re.compile(r"\bSHA[-_]?384\b", re.IGNORECASE),
        "SHA-384",
        "hash",
    ),
    (
        re.compile(r"\bSHA[-_]?512\b", re.IGNORECASE),
        "SHA-512",
        "hash",
    ),
    (
        re.compile(r"\bSHA[-_]?1\b", re.IGNORECASE),
        "SHA-1",
        "hash",
    ),
    (
        re.compile(r"\bMD5\b", re.IGNORECASE),
        "MD5",
        "hash",
    ),
]


# ---------------------------------------------------------------------------
# TLS / SSL / SSH
# ---------------------------------------------------------------------------


_PROTOCOL_VERSION_RE = re.compile(
    r"\b(TLS|SSL)"
    r"[\s_-]*v?"
    r"(1\.3|1\.2|1\.1|1\.0|1|2|3)\b",
    re.IGNORECASE,
)


_SSH_EVIDENCE_RE = re.compile(
    r"\bssh-keygen\b"
    r"|\bauthorized_keys\b"
    r"|\bid_rsa\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Certificate / key file references
# ---------------------------------------------------------------------------


_CERT_FILE_RE = re.compile(
    r"[\w./\\*:-]+\.(?:crt|cer|pem|der|p12|pfx)\b",
    re.IGNORECASE,
)


_KEY_FILE_RE = re.compile(
    r"[\w./\\*:-]+\.key\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# ARG / ENV crypto context
# ---------------------------------------------------------------------------


_CONTEXT_VAR_NAMES = {
    "SSL_CERTIFICATE",
    "SSL_CERTIFICATE_KEY",
    "TLS_CERT",
    "TLS_KEY",
    "CERT_FILE",
    "CERTIFICATE_FILE",
    "KEY_FILE",
    "PRIVATE_KEY",
    "SSL_CERT",
    "SSL_KEY",
    "TLS_VERSION",
    "SSL_VERSION",
    "RSA_KEY_SIZE",
    "PRIVATE_KEY_PATH",
    "PUBLIC_KEY_PATH",
    "CA_CERT",
    "CA_CERTIFICATE",
}


# ---------------------------------------------------------------------------
# Dockerfile preprocessing
# ---------------------------------------------------------------------------


@dataclass
class _Statement:
    """A logical Dockerfile statement."""

    line_number: int
    flat: str
    instruction: Optional[str]
    remainder: str


def _split_statements(content: str) -> List[_Statement]:
    """
    Split Dockerfile text into logical statements.

    Continuation lines ending with '\\' are joined.
    Full-line comments and blank lines are ignored.
    """

    raw_lines = content.splitlines()
    statements: List[_Statement] = []

    i = 0
    n = len(raw_lines)

    while i < n:
        raw = raw_lines[i]
        stripped = raw.strip()

        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        start_line_no = i + 1

        parts = [raw.rstrip()]
        current = raw.rstrip()
        j = i

        while current.endswith("\\") and j + 1 < n:
            j += 1
            current = raw_lines[j].rstrip()
            parts.append(current)

        flat = " ".join(
            part[:-1].strip() if part.endswith("\\") else part.strip()
            for part in parts
        )

        flat = re.sub(r"\s+", " ", flat).strip()

        match = INSTRUCTION_RE.match(flat)

        instruction = None
        remainder = flat

        if match:
            candidate = match.group(1).upper()

            known_instructions = TARGET_INSTRUCTIONS | {
                "WORKDIR",
                "EXPOSE",
                "USER",
                "VOLUME",
                "SHELL",
                "HEALTHCHECK",
                "ONBUILD",
                "STOPSIGNAL",
                "MAINTAINER",
                "LABEL",
            }

            if candidate in known_instructions:
                instruction = candidate
                remainder = match.group(2)

        statements.append(
            _Statement(
                line_number=start_line_no,
                flat=flat,
                instruction=instruction,
                remainder=remainder,
            )
        )

        i = j + 1

    return statements


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------


def _redact_if_secret(text: str) -> Tuple[str, bool]:
    """
    Return (possibly redacted text, whether secret material was detected).
    """

    if PEM_HEADER_RE.search(text):
        return "<redacted: embedded private key material>", True

    return text, False


# ---------------------------------------------------------------------------
# Package detection
# ---------------------------------------------------------------------------


def _detect_package_installs(
    stmt: _Statement,
    file_path: str,
) -> List[DockerCryptoFinding]:

    findings: List[DockerCryptoFinding] = []

    if stmt.instruction != "RUN":
        return findings

    for pattern in _PKG_MANAGER_PATTERNS:
        for match in pattern.finditer(stmt.flat):
            package_blob = match.group("pkgs")

            tokens = [
                token
                for token in re.split(r"\s+", package_blob.strip())
                if token and not token.startswith("-")
            ]

            for token in tokens:
                name = (
                    token.split("=")[0]
                    .split(":")[0]
                    .strip()
                    .lower()
                )

                if name not in KNOWN_CRYPTO_LIBS:
                    continue

                library, confidence = KNOWN_CRYPTO_LIBS[name]

                findings.append(
                    DockerCryptoFinding(
                        artifact_type="library",
                        file_path=file_path,
                        line_number=stmt.line_number,
                        code_snippet=stmt.flat,
                        docker_instruction=stmt.instruction,
                        library=library,
                        evidence_type="package_install",
                        detection_method="pattern",
                        confidence=confidence,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# OpenSSL command detection
# ---------------------------------------------------------------------------


def _detect_openssl_commands(
    stmt: _Statement,
    file_path: str,
) -> List[DockerCryptoFinding]:

    findings: List[DockerCryptoFinding] = []

    if stmt.instruction not in ("RUN", "CMD", "ENTRYPOINT"):
        return findings

    for match in OPENSSL_CMD_RE.finditer(stmt.flat):

        subcmd = match.group(1).lower()

        snippet, _ = _redact_if_secret(stmt.flat)

        # ---------------------------------------------------------------
        # RSA / general key generation
        # ---------------------------------------------------------------

        if subcmd in _KEYGEN_SUBCOMMANDS:

            algorithm = "RSA"

            algorithm_match = _GENPKEY_ALGO_RE.search(stmt.flat)

            if algorithm_match:
                algorithm = algorithm_match.group(1).upper()

            key_size = None

            bits_match = _RSA_KEYGEN_BITS_RE.search(stmt.flat)

            if bits_match:
                key_size = int(bits_match.group(1))
            else:
                size_match = _COMMON_KEY_SIZES.search(stmt.flat)

                if size_match:
                    key_size = int(size_match.group(1))

            findings.append(
                DockerCryptoFinding(
                    artifact_type="algorithm",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    algorithm=algorithm,
                    key_size=key_size,
                    library="OpenSSL",
                    evidence_type="openssl_command",
                    detection_method="regex/pattern",
                    confidence=0.95,
                )
            )

        # ---------------------------------------------------------------
        # EC / EC parameter generation
        # ---------------------------------------------------------------

        elif subcmd in _EC_SUBCOMMANDS:

            curve_match = _EC_CURVE_NAME_RE.search(stmt.flat)

            algorithm = "EC"

            if curve_match:
                algorithm = f"EC ({curve_match.group(1)})"

            findings.append(
                DockerCryptoFinding(
                    artifact_type="algorithm",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    algorithm=algorithm,
                    library="OpenSSL",
                    evidence_type="openssl_command",
                    detection_method="regex/pattern",
                    confidence=0.90,
                )
            )

        # ---------------------------------------------------------------
        # Hashing with openssl dgst
        # ---------------------------------------------------------------

        elif subcmd == "dgst":

            hash_match = _DGST_HASH_RE.search(stmt.flat)

            algorithm = None

            if hash_match:
                algorithm = _DGST_HASH_CANON.get(
                    hash_match.group(1).lower()
                )

            findings.append(
                DockerCryptoFinding(
                    artifact_type="algorithm",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    algorithm=algorithm,
                    library="OpenSSL",
                    evidence_type="openssl_command",
                    detection_method="regex/pattern",
                    confidence=0.90 if hash_match else 0.60,
                )
            )

        # ---------------------------------------------------------------
        # Symmetric encryption with openssl enc
        # ---------------------------------------------------------------

        elif subcmd == "enc":

            cipher_match = _ENC_CIPHER_RE.search(stmt.flat)

            algorithm = None

            if cipher_match:
                algorithm = cipher_match.group(1).upper()

            findings.append(
                DockerCryptoFinding(
                    artifact_type="algorithm",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    algorithm=algorithm,
                    library="OpenSSL",
                    evidence_type="openssl_command",
                    detection_method="regex/pattern",
                    confidence=0.90 if cipher_match else 0.60,
                )
            )

        # ---------------------------------------------------------------
        # TLS connection with openssl s_client
        # ---------------------------------------------------------------

        elif subcmd == "s_client":

            tls_match = _TLS_FLAG_RE.search(stmt.flat)

            protocol_version = None

            if tls_match:
                protocol_version = _TLS_FLAG_CANON.get(
                    tls_match.group(1).lower()
                )

            findings.append(
                DockerCryptoFinding(
                    artifact_type="protocol",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    protocol="TLS",
                    protocol_version=protocol_version,
                    library="OpenSSL",
                    evidence_type="openssl_command",
                    detection_method="regex/pattern",
                    confidence=0.85,
                )
            )

        # ---------------------------------------------------------------
        # CERTIFICATE GENERATION
        #
        # IMPORTANT:
        #
        # Only `openssl req -x509` is treated as certificate generation.
        #
        # We deliberately do NOT classify:
        #   openssl x509 ...
        #   openssl verify ...
        #   openssl pkcs12 ...
        #   openssl ca ...
        #
        # as certificate_generation.
        # ---------------------------------------------------------------

        elif (
            subcmd == "req"
            and re.search(r"-x509\b", stmt.flat, re.IGNORECASE)
        ):

            findings.append(
                DockerCryptoFinding(
                    artifact_type="certificate_generation",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    library="OpenSSL",
                    evidence_type="openssl_command",
                    detection_method="regex/pattern",
                    confidence=0.95,
                )
            )

            # Example:
            # openssl req -new -x509 -newkey rsa:4096 ...
            #
            # The command reveals the algorithm and key size used to
            # generate the certificate's key.

            newkey_match = _NEWKEY_RE.search(stmt.flat)

            if newkey_match:

                kind = newkey_match.group(1).lower()
                parameter = newkey_match.group(2)

                if kind in ("rsa", "dsa"):

                    findings.append(
                        DockerCryptoFinding(
                            artifact_type="algorithm",
                            file_path=file_path,
                            line_number=stmt.line_number,
                            code_snippet=snippet,
                            docker_instruction=stmt.instruction,
                            algorithm=kind.upper(),
                            key_size=(
                                int(parameter)
                                if parameter.isdigit()
                                else None
                            ),
                            library="OpenSSL",
                            evidence_type="openssl_command",
                            detection_method="regex/pattern",
                            confidence=0.95,
                        )
                    )

                elif kind == "ec":

                    findings.append(
                        DockerCryptoFinding(
                            artifact_type="algorithm",
                            file_path=file_path,
                            line_number=stmt.line_number,
                            code_snippet=snippet,
                            docker_instruction=stmt.instruction,
                            algorithm=f"EC ({parameter})",
                            library="OpenSSL",
                            evidence_type="openssl_command",
                            detection_method="regex/pattern",
                            confidence=0.90,
                        )
                    )

    return findings


def _line_has_openssl_command(stmt: _Statement) -> bool:
    """Return True if the statement contains a recognized OpenSSL command."""

    return bool(OPENSSL_CMD_RE.search(stmt.flat))


# ---------------------------------------------------------------------------
# Generic algorithm detection
# ---------------------------------------------------------------------------


def _detect_generic_algorithms(
    stmt: _Statement,
    file_path: str,
) -> List[DockerCryptoFinding]:

    """
    Detect explicit algorithm references outside OpenSSL-specific commands.
    """

    findings: List[DockerCryptoFinding] = []

    if stmt.instruction not in TARGET_INSTRUCTIONS:
        return findings

    if _line_has_openssl_command(stmt):
        return findings

    consumed: List[Tuple[int, int]] = []

    for pattern, canonical, _category in _ALGO_PATTERNS:

        for match in pattern.finditer(stmt.flat):

            span = match.span()

            # Prevent overlapping patterns from reporting the same text.
            if any(
                not (span[1] <= start or span[0] >= end)
                for start, end in consumed
            ):
                continue

            consumed.append(span)

            key_size = None
            algorithm_name = canonical

            if canonical == "RSA":
                if match.groups() and match.group(1):
                    key_size = int(match.group(1))

            elif canonical == "AES":

                bits = match.group(1) if match.groups() else None
                mode = (
                    match.group(2)
                    if len(match.groups()) > 1
                    else None
                )

                if bits:
                    algorithm_name = f"AES-{bits}"

                if mode:
                    algorithm_name += f"-{mode.upper()}"

            snippet, _ = _redact_if_secret(stmt.flat)

            findings.append(
                DockerCryptoFinding(
                    artifact_type="algorithm",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    algorithm=algorithm_name,
                    key_size=key_size,
                    evidence_type="algorithm_reference",
                    detection_method="regex/pattern",
                    confidence=0.75,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Protocol detection
# ---------------------------------------------------------------------------


def _detect_protocols(
    stmt: _Statement,
    file_path: str,
) -> List[DockerCryptoFinding]:

    """
    Detect TLS/SSL versions and SSH evidence outside OpenSSL commands.

    ENV/ARG protocol configuration is handled separately.
    """

    findings: List[DockerCryptoFinding] = []

    if stmt.instruction not in TARGET_INSTRUCTIONS:
        return findings

    if stmt.instruction in ("ENV", "ARG"):
        return findings

    if _line_has_openssl_command(stmt):
        return findings

    for match in _PROTOCOL_VERSION_RE.finditer(stmt.flat):

        family = match.group(1).upper()
        version = match.group(2)

        canonical_version = f"{family}v{version}"

        findings.append(
            DockerCryptoFinding(
                artifact_type="protocol",
                file_path=file_path,
                line_number=stmt.line_number,
                code_snippet=stmt.flat,
                docker_instruction=stmt.instruction,
                protocol=family,
                protocol_version=canonical_version,
                evidence_type="protocol_version",
                detection_method="pattern",
                confidence=0.90,
            )
        )

    if _SSH_EVIDENCE_RE.search(stmt.flat):

        findings.append(
            DockerCryptoFinding(
                artifact_type="protocol",
                file_path=file_path,
                line_number=stmt.line_number,
                code_snippet=stmt.flat,
                docker_instruction=stmt.instruction,
                protocol="SSH",
                evidence_type="ssh_evidence",
                detection_method="pattern",
                confidence=0.75,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Certificate / key file references
# ---------------------------------------------------------------------------


def _detect_certificate_and_key_files(
    stmt: _Statement,
    file_path: str,
) -> List[DockerCryptoFinding]:

    """
    Detect static certificate/key file references in COPY, ADD and RUN.

    These are references, not proof that the actual file contents are
    certificates or keys.
    """

    findings: List[DockerCryptoFinding] = []

    if stmt.instruction not in ("COPY", "ADD", "RUN"):
        return findings

    seen_paths = set()

    key_keywords_re = re.compile(
        r"(key|priv|private|id_rsa|id_dsa|id_ecdsa|id_ed25519|secret)",
        re.IGNORECASE,
    )

    cert_keywords_re = re.compile(
        r"(cert|crt|cer|ca|chain|fullchain)",
        re.IGNORECASE,
    )

    # Look for common certificate/key filenames.
    file_matches = re.finditer(
        r"""
        (
            [\w./\\*:-]+\.(?:crt|cer|pem|der|p12|pfx|key)
            |
            [\w./\\*:-]*id_rsa
            |
            [\w./\\*:-]*id_dsa
            |
            [\w./\\*:-]*id_ecdsa
            |
            [\w./\\*:-]*id_ed25519
        )
        \b
        """,
        stmt.flat,
        re.IGNORECASE | re.VERBOSE,
    )

    for match in file_matches:

        path = match.group(1)

        if path in seen_paths:
            continue

        seen_paths.add(path)

        path_lower = path.lower()
        extension = os.path.splitext(path_lower)[1]

        # ---------------------------------------------------------------
        # Key reference
        # ---------------------------------------------------------------

        if (
            key_keywords_re.search(path_lower)
            or extension == ".key"
        ):

            findings.append(
                DockerCryptoFinding(
                    artifact_type="key_reference",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=stmt.flat,
                    docker_instruction=stmt.instruction,
                    evidence_type="key_file_reference",
                    detection_method="pattern",
                    confidence=0.80,
                )
            )

        # ---------------------------------------------------------------
        # Clear certificate reference
        # ---------------------------------------------------------------

        elif (
            cert_keywords_re.search(path_lower)
            or extension in (".crt", ".cer", ".p12", ".pfx")
        ):

            findings.append(
                DockerCryptoFinding(
                    artifact_type="certificate_reference",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=stmt.flat,
                    docker_instruction=stmt.instruction,
                    evidence_type="certificate_file_reference",
                    detection_method="pattern",
                    confidence=0.80,
                )
            )

        # ---------------------------------------------------------------
        # Ambiguous PEM / DER
        # ---------------------------------------------------------------

        elif extension in (".pem", ".der"):

            findings.append(
                DockerCryptoFinding(
                    artifact_type="certificate_reference",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=stmt.flat,
                    docker_instruction=stmt.instruction,
                    evidence_type="ambiguous_pem_reference",
                    detection_method="pattern",
                    confidence=0.50,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# ENV / ARG context detection
# ---------------------------------------------------------------------------


def _detect_env_arg_context(
    stmt: _Statement,
    file_path: str,
) -> List[DockerCryptoFinding]:

    """
    Detect ENV/ARG variables whose names or values indicate cryptographic
    configuration.
    """

    findings: List[DockerCryptoFinding] = []

    if stmt.instruction not in ("ENV", "ARG"):
        return findings

    remainder = stmt.remainder.strip()

    assignments = re.findall(
        r"""
        ([A-Za-z_][A-Za-z0-9_]*)
        \s*=\s*
        (
            "(?:[^"\\]|\\.)*"
            |
            '(?:[^'\\]|\\.)*'
            |
            \S+
        )
        """,
        remainder,
        re.VERBOSE,
    )

    # Support:
    #
    #   ENV TLS_KEY /etc/tls/server.key
    #
    # in addition to:
    #
    #   ENV TLS_KEY=/etc/tls/server.key

    if not assignments and remainder:

        parts = remainder.split(None, 1)

        if parts:

            variable = parts[0]
            value = parts[1] if len(parts) > 1 else ""

            assignments = [(variable, value)]

    key_keywords_re = re.compile(
        r"(key|priv|private|secret)",
        re.IGNORECASE,
    )

    cert_keywords_re = re.compile(
        r"(cert|crt|cer|ca)",
        re.IGNORECASE,
    )

    for variable, raw_value in assignments:

        variable_upper = variable.upper()

        value = raw_value.strip("\"'")

        snippet, _ = _redact_if_secret(stmt.flat)

        # ---------------------------------------------------------------
        # Unknown variable names can still reveal references through
        # their values.
        # ---------------------------------------------------------------

        if variable_upper not in _CONTEXT_VAR_NAMES:

            value_lower = value.lower()

            if (
                key_keywords_re.search(value_lower)
                or value_lower.endswith(".key")
            ):

                findings.append(
                    DockerCryptoFinding(
                        artifact_type="key_reference",
                        file_path=file_path,
                        line_number=stmt.line_number,
                        code_snippet=snippet,
                        docker_instruction=stmt.instruction,
                        evidence_type="key_file_reference",
                        detection_method="pattern",
                        confidence=0.70,
                    )
                )

            elif (
                cert_keywords_re.search(value_lower)
                or any(
                    value_lower.endswith(extension)
                    for extension in (
                        ".crt",
                        ".cer",
                        ".p12",
                        ".pfx",
                        ".pem",
                    )
                )
            ):

                findings.append(
                    DockerCryptoFinding(
                        artifact_type="certificate_reference",
                        file_path=file_path,
                        line_number=stmt.line_number,
                        code_snippet=snippet,
                        docker_instruction=stmt.instruction,
                        evidence_type="certificate_file_reference",
                        detection_method="pattern",
                        confidence=0.70,
                    )
                )

            continue

        # ---------------------------------------------------------------
        # TLS / SSL version
        # ---------------------------------------------------------------

        if variable_upper in ("TLS_VERSION", "SSL_VERSION"):

            version_match = (
                _PROTOCOL_VERSION_RE.search(value)
                or _PROTOCOL_VERSION_RE.search(stmt.flat)
            )

            protocol = (
                "TLS"
                if variable_upper == "TLS_VERSION"
                else "SSL"
            )

            protocol_version = None

            if version_match:
                protocol_version = (
                    f"{version_match.group(1).upper()}v"
                    f"{version_match.group(2)}"
                )
            elif value:
                protocol_version = value

            findings.append(
                DockerCryptoFinding(
                    artifact_type="protocol",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    protocol=protocol,
                    protocol_version=protocol_version,
                    evidence_type="env_config",
                    detection_method="pattern",
                    confidence=0.90,
                )
            )

        # ---------------------------------------------------------------
        # RSA key size
        # ---------------------------------------------------------------

        elif variable_upper == "RSA_KEY_SIZE":

            key_size = int(value) if value.isdigit() else None

            findings.append(
                DockerCryptoFinding(
                    artifact_type="algorithm",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    algorithm="RSA",
                    key_size=key_size,
                    evidence_type="env_config",
                    detection_method="pattern",
                    confidence=0.85,
                )
            )

        # ---------------------------------------------------------------
        # Generic key configuration
        # ---------------------------------------------------------------

        elif "KEY" in variable_upper:

            findings.append(
                DockerCryptoFinding(
                    artifact_type="key_reference",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    evidence_type="env_config",
                    detection_method="pattern",
                    confidence=0.85,
                )
            )

        # ---------------------------------------------------------------
        # Certificate configuration
        # ---------------------------------------------------------------

        else:

            findings.append(
                DockerCryptoFinding(
                    artifact_type="certificate_reference",
                    file_path=file_path,
                    line_number=stmt.line_number,
                    code_snippet=snippet,
                    docker_instruction=stmt.instruction,
                    evidence_type="env_config",
                    detection_method="pattern",
                    confidence=0.85,
                )
            )

    # Never allow embedded private-key material to appear in output.

    if (
        PEM_HEADER_RE.search(stmt.flat)
        and not any(
            finding.evidence_type == "env_config"
            for finding in findings
        )
    ):

        findings.append(
            DockerCryptoFinding(
                artifact_type="key_reference",
                file_path=file_path,
                line_number=stmt.line_number,
                code_snippet="<redacted: embedded private key material>",
                docker_instruction=stmt.instruction,
                evidence_type="embedded_private_key",
                detection_method="pattern",
                confidence=0.99,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


def _scan_statements(
    statements: List[_Statement],
    file_path: str,
) -> List[Dict[str, Any]]:

    findings: List[DockerCryptoFinding] = []

    for statement in statements:

        if statement.instruction not in TARGET_INSTRUCTIONS:
            continue

        findings.extend(
            _detect_package_installs(
                statement,
                file_path,
            )
        )

        findings.extend(
            _detect_openssl_commands(
                statement,
                file_path,
            )
        )

        findings.extend(
            _detect_generic_algorithms(
                statement,
                file_path,
            )
        )

        findings.extend(
            _detect_protocols(
                statement,
                file_path,
            )
        )

        findings.extend(
            _detect_certificate_and_key_files(
                statement,
                file_path,
            )
        )

        findings.extend(
            _detect_env_arg_context(
                statement,
                file_path,
            )
        )

    findings.sort(
        key=lambda finding: (
            finding.line_number,
            finding.artifact_type,
        )
    )

    return [
        finding.to_dict()
        for finding in findings
    ]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def scan_dockerfile_content(
    content: str,
    file_path: str = "Dockerfile",
) -> List[Dict[str, Any]]:
    """
    Analyze Dockerfile text already in memory.

    Args:
        content:
            Full Dockerfile text.

        file_path:
            Path/name stored in the resulting findings.

    Returns:
        List of structured finding dictionaries.

    Raises:
        DockerDetectorError:
            If content is None.
    """

    if content is None:
        raise DockerDetectorError(
            "Dockerfile content must not be None"
        )

    statements = _split_statements(content)

    return _scan_statements(
        statements,
        file_path,
    )


def scan_dockerfile(
    file_path: str,
) -> List[Dict[str, Any]]:
    """
    Read and analyze a Dockerfile from disk.

    Raises:
        DockerDetectorError:
            If the file does not exist, is not a regular file,
            or cannot be decoded as UTF-8.
    """

    if not os.path.isfile(file_path):
        raise DockerDetectorError(
            f"Dockerfile not found: {file_path}"
        )

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="strict",
        ) as file_handle:

            content = file_handle.read()

    except (OSError, UnicodeDecodeError) as exc:

        raise DockerDetectorError(
            f"Could not read Dockerfile {file_path}: {exc}"
        ) from exc

    return scan_dockerfile_content(
        content,
        file_path=file_path,
    )


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


if __name__ == "__main__":

    import json
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python docker_detector.py "
            "<path-to-Dockerfile>"
        )
        raise SystemExit(1)

    results = scan_dockerfile(sys.argv[1])

    print(
        json.dumps(
            results,
            indent=2,
        )
    )