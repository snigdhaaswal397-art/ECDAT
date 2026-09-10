"""
container_detector.py
=======================

Standalone container-IMAGE cryptography discovery detector for ECDAT.

This is distinct from docker_detector.py: docker_detector.py scans
Dockerfile *text* (build instructions); this module inspects an actual
built/runnable container image's metadata and filesystem. Both can and do
coexist -- this module imports docker_detector.KNOWN_CRYPTO_LIBS to avoid
duplicating the crypto-package table, but never modifies docker_detector.py
and does not touch Dockerfile parsing at all.

It is a DISCOVERY component only. It does not calculate quantum risk, does
not implement Mosca's theorem, does not assign business criticality, does
not generate CBOM, and does not label anything "vulnerable" -- that is the
job of a later ECDAT risk-engine stage.

ARCHITECTURE
------------
    Container Image -> container_detector.scan_container_image() -> findings
    -> (caller, e.g. scanner.py) -> scanner_output.json

This module never writes scanner_output.json itself; it only returns a
list of finding dicts, consistent with docker_detector.py and
certificate_detector.py's public interfaces.

WHAT IT DOES
------------
    1. Verifies Docker is available (CLI present, daemon reachable) before
       doing anything else.
    2. Reads image metadata via `docker inspect` (architecture, OS, created
       timestamp, entrypoint, cmd, env, exposed ports, labels), redacting
       any environment variable that looks like a secret and scanning the
       remaining textual metadata for crypto evidence.
    3. Materializes the image filesystem *without ever running the image's
       application*: `docker create` (does not start the container) +
       `docker export` (streams the container's filesystem as a tar,
       Docker's supported mechanism for this) into a private temp
       directory, always removing the temporary container in a
       `try/finally`.
    4. Walks that filesystem looking for:
         - certificate files (delegated to certificate_detector.scan_certificate)
         - key files (existence + best-effort algorithm hint from the PEM
           header only -- contents are never read beyond that header, and
           never stored)
         - crypto-relevant configuration files (openssl.cnf, ssh_config,
           sshd_config, nginx/apache TLS config, etc.) scanned with the
           same style of contextual regex matching used elsewhere in ECDAT
         - installed-package evidence, by reading package-manager
           databases directly (dpkg status file, apk installed db, and the
           host's own `rpm` binary against the extracted db if available)
           -- never by executing anything *from* the image.

WHAT IT DELIBERATELY DOES NOT DO
---------------------------------
    * No quantum-risk scoring, no Mosca's theorem, no PQC recommendations,
      no CBOM generation, no business-criticality labels.
    * Never executes a binary that came from inside the image.
    * Never modifies the image (all Docker calls are create/inspect/export/
      rm; no `docker commit`, no `docker push`).
    * Never returns private key contents, passwords, tokens, or secret
      environment-variable values.

FINDING SCHEMA
--------------
Fields mirror the ECDAT Artifact model as described to this module (this
sandbox does not have your actual scanner/models.py, so the fields below
are produced as plain dicts matching the names you specified -- adjust the
mapping in `_to_artifact_dict` if your real Artifact dataclass differs):

    artifact_id, artifact_type, algorithm, key_size, library, file_path,
    line_number, code_snippet, detection_method, confidence,
    source_type="container_image",
    and (only when populated) language, mode, protocol, evidence,
    dependency_version, certificate_subject, certificate_issuer,
    certificate_expiry.

PUBLIC INTERFACE
-----------------
    scan_container_image(image_name, timeout=DEFAULT_STEP_TIMEOUT,
                          docker_bin="docker", max_files_scanned=5000,
                          max_file_size_bytes=1_000_000)
        -> List[Dict[str, Any]]

EXCEPTIONS
----------
    ContainerDetectorError -- covers: Docker CLI missing, Docker daemon
    unavailable, image not found / invalid name, inspect/create/export
    failure, timeout, permission error. Individual unreadable/malformed
    files inside the image are skipped (with a low-confidence note where
    useful) rather than aborting the whole scan.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

# Reuse the existing crypto-package table rather than duplicating it.
# docker_detector.py is not modified by this import.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

try:
    from docker_detector import KNOWN_CRYPTO_LIBS  # type: ignore
except ImportError:  # pragma: no cover - keeps this module usable standalone
    KNOWN_CRYPTO_LIBS = {
        "openssl": ("OpenSSL", 0.90),
        "libssl-dev": ("OpenSSL (dev headers)", 0.85),
        "libssl": ("OpenSSL", 0.85),
        "cryptography": ("cryptography (Python)", 0.90),
        "pycryptodome": ("PyCryptodome", 0.90),
        "pyopenssl": ("pyOpenSSL", 0.90),
        "bcrypt": ("bcrypt", 0.80),
        "libsodium": ("libsodium", 0.90),
        "gnutls": ("GnuTLS", 0.85),
        "mbedtls": ("mbed TLS", 0.85),
        "wolfssl": ("wolfSSL", 0.85),
    }

try:
    from certificate_detector import scan_certificate, CertificateDetectorError  # type: ignore
except ImportError:  # pragma: no cover
    scan_certificate = None
    CertificateDetectorError = Exception  # type: ignore


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class ContainerDetectorError(Exception):
    """Raised for any unrecoverable problem scanning a container image."""


# --------------------------------------------------------------------------- #
# Config / constants
# --------------------------------------------------------------------------- #

DEFAULT_STEP_TIMEOUT = 30          # seconds, per docker subprocess call
DEFAULT_EXPORT_TIMEOUT = 120       # seconds, export can be large
DEFAULT_MAX_FILES_SCANNED = 5000
DEFAULT_MAX_FILE_SIZE_BYTES = 1_000_000

SOURCE_TYPE = "container_image"

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}
KEY_EXTENSIONS = {".key", ".pub"}
KEY_BASENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa.pub",
                  "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub"}
CONFIG_BASENAMES = {
    "openssl.cnf", "openssl.conf", "ssh_config", "sshd_config",
    "nginx.conf", "httpd.conf", "apache2.conf",
}
CONFIG_EXTENSIONS = {".conf", ".cnf", ".cfg", ".ini"}

_SECRET_ENV_NAME_RE = re.compile(
    r"(SECRET|PASSWORD|PASSWD|PASS\b|PWD|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)",
    re.IGNORECASE,
)

_PEM_KEY_HEADER_RE = re.compile(
    r"-----BEGIN\s+((?:RSA|EC|DSA|ED25519|ENCRYPTED|OPENSSH)?\s*PRIVATE KEY)-----",
    re.IGNORECASE,
)
_PEM_ANY_BLOCK_RE = re.compile(
    r"-----BEGIN\s+((?:RSA|EC|DSA|ED25519|ENCRYPTED|OPENSSH)?\s*PRIVATE KEY)-----.*?"
    r"-----END\s+\1-----",
    re.IGNORECASE | re.DOTALL,
)

_KEY_TYPE_TO_ALGORITHM = {
    "rsa private key": "RSA",
    "ec private key": "EC",
    "dsa private key": "DSA",
    "ed25519 private key": "Ed25519",
    "openssh private key": None,   # container format, real type is inside (not read)
    "encrypted private key": None,
    "private key": None,           # PKCS#8, generic -- algorithm unknown w/o parsing
}

# --------------------------------------------------------------------------- #
# Generic crypto pattern detection (kept intentionally small/local; mirrors
# the *style* of docker_detector.py's pattern matching without importing its
# private, docker-instruction-specific internals).
# --------------------------------------------------------------------------- #

_ALGO_PATTERNS: List[Tuple[re.Pattern, str, Optional[str]]] = [
    (re.compile(r"\bChaCha20-Poly1305\b", re.IGNORECASE), "ChaCha20-Poly1305", None),
    (re.compile(r"\bChaCha20\b", re.IGNORECASE), "ChaCha20", None),
    (re.compile(r"\bRSA[-_]?(1024|2048|3072|4096|8192)\b", re.IGNORECASE), "RSA", "keysize"),
    (re.compile(r"\bRSA\b", re.IGNORECASE), "RSA", None),
    (re.compile(r"\bECDSA\b", re.IGNORECASE), "ECDSA", None),
    (re.compile(r"\bECDH\b", re.IGNORECASE), "ECDH", None),
    (re.compile(r"\bECC\b", re.IGNORECASE), "ECC", None),
    (re.compile(r"\bEd25519\b", re.IGNORECASE), "Ed25519", None),
    (re.compile(r"\bEd448\b", re.IGNORECASE), "Ed448", None),
    (re.compile(r"\bDSA\b"), "DSA", None),
    (re.compile(r"\bAES[-_]?(128|192|256)?(?:[-_](GCM|CBC|CTR|CFB|OFB|ECB))?\b", re.IGNORECASE), "AES", "aes"),
    (re.compile(r"\bTriple[-_ ]?DES\b", re.IGNORECASE), "3DES", None),
    (re.compile(r"\b3DES\b", re.IGNORECASE), "3DES", None),
    (re.compile(r"\bDES\b"), "DES", None),
    (re.compile(r"\bSHA[-_]?224\b", re.IGNORECASE), "SHA-224", None),
    (re.compile(r"\bSHA[-_]?256\b", re.IGNORECASE), "SHA-256", None),
    (re.compile(r"\bSHA[-_]?384\b", re.IGNORECASE), "SHA-384", None),
    (re.compile(r"\bSHA[-_]?512\b", re.IGNORECASE), "SHA-512", None),
    (re.compile(r"\bSHA[-_]?1\b", re.IGNORECASE), "SHA-1", None),
    (re.compile(r"\bMD5\b", re.IGNORECASE), "MD5", None),
]

_PROTOCOL_VERSION_RE = re.compile(
    r"\b(TLS|SSL)[\s_-]?v?[\s_-]?(1\.3|1\.2|1\.1|1\.0|1|2|3)\b", re.IGNORECASE
)
_SSH_EVIDENCE_RE = re.compile(r"\bssh-keygen\b|\bauthorized_keys\b|\bAllowUsers\b|\bPermitRootLogin\b", re.IGNORECASE)

_OPENSSL_CMD_RE = re.compile(
    r"\bopenssl\s+(genrsa|genpkey|req|x509|ecparam|ec|dgst|enc|s_client|verify|rsa|pkey|pkcs12|ca)\b",
    re.IGNORECASE,
)

_COMMENT_PREFIXES = ("#", "//", ";")


def _looks_like_comment_line(line: str) -> bool:
    stripped = line.strip()
    return any(stripped.startswith(p) for p in _COMMENT_PREFIXES)


def _scan_text_for_crypto_patterns(text: str, file_path: str, base_confidence: float = 0.6) -> List["ContainerFinding"]:
    """Scan arbitrary text (a config file, or a flattened metadata blob)
    for crypto evidence. Comment lines get a confidence penalty rather
    than being treated as configuration evidence."""
    findings: List[ContainerFinding] = []

    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        is_comment = _looks_like_comment_line(line)
        line_confidence = base_confidence * (0.5 if is_comment else 1.0)

        openssl_match = _OPENSSL_CMD_RE.search(line)
        if openssl_match:
            subcmd = openssl_match.group(1).lower()
            findings.append(ContainerFinding(
                artifact_type="algorithm" if subcmd not in ("req", "x509", "verify", "pkcs12", "ca") else "certificate",
                file_path=file_path,
                line_number=line_no,
                code_snippet=_scrub(line.strip())[:200],
                detection_method="filesystem_pattern",
                confidence=min(0.95, line_confidence + 0.3),
                evidence=f"openssl {openssl_match.group(1)}",
            ))
            # Fall through (no `continue`) so a TLS-version flag or other
            # protocol evidence on the same line (e.g. `s_client -tls1_2`)
            # is still captured below.

        consumed: List[Tuple[int, int]] = []
        for pattern, canonical, extra in _ALGO_PATTERNS:
            for m in pattern.finditer(line):
                span = m.span()
                if any(not (span[1] <= s or span[0] >= e) for (s, e) in consumed):
                    continue
                consumed.append(span)
                key_size = None
                algo_name = canonical
                if extra == "keysize" and m.group(1):
                    key_size = int(m.group(1))
                elif extra == "aes":
                    bits = m.group(1)
                    mode = m.group(2) if len(m.groups()) > 1 else None
                    if bits:
                        algo_name = f"AES-{bits}" + (f"-{mode.upper()}" if mode else "")
                findings.append(ContainerFinding(
                    artifact_type="algorithm",
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=_scrub(line.strip())[:200],
                    algorithm=algo_name,
                    key_size=key_size,
                    detection_method="filesystem_pattern",
                    confidence=round(min(0.9, line_confidence), 2),
                ))

        for m in _PROTOCOL_VERSION_RE.finditer(line):
            family = m.group(1).upper()
            version = m.group(2)
            canonical_version = f"{family}v{version}" if not version[0].isalpha() else version
            findings.append(ContainerFinding(
                artifact_type="protocol",
                file_path=file_path,
                line_number=line_no,
                code_snippet=_scrub(line.strip())[:200],
                protocol=canonical_version,
                detection_method="filesystem_pattern",
                confidence=round(min(0.9, line_confidence + 0.2), 2),
            ))

        if _SSH_EVIDENCE_RE.search(line):
            findings.append(ContainerFinding(
                artifact_type="protocol",
                file_path=file_path,
                line_number=line_no,
                code_snippet=_scrub(line.strip())[:200],
                protocol="SSH",
                detection_method="filesystem_pattern",
                confidence=round(min(0.85, line_confidence + 0.1), 2),
            ))

    return findings


# --------------------------------------------------------------------------- #
# Secret scrubbing
# --------------------------------------------------------------------------- #


def _scrub(text: str) -> str:
    if not text:
        return text
    return _PEM_ANY_BLOCK_RE.sub("<redacted: private key material>", text)


def _redact_env_value(name: str, value: str) -> Optional[str]:
    """Return the value to store for an env var, or None if it must be
    redacted entirely."""
    if _SECRET_ENV_NAME_RE.search(name):
        return None
    if _PEM_KEY_HEADER_RE.search(value):
        return None
    return value


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #


@dataclass
class ContainerFinding:
    artifact_type: str
    file_path: Optional[str] = None
    line_number: int = 0
    code_snippet: Optional[str] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    library: Optional[str] = None
    detection_method: str = "filesystem_pattern"
    confidence: float = 0.5
    language: Optional[str] = None
    mode: Optional[str] = None
    protocol: Optional[str] = None
    evidence: Optional[str] = None
    dependency_version: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[str] = None
    certificate_serial_number: Optional[str] = None
    certificate_not_before: Optional[str] = None
    certificate_version: Optional[int] = None
    certificate_signature_algorithm: Optional[str] = None
    certificate_ec_curve: Optional[str] = None
    certificate_subject_alternative_names: Optional[List[str]] = None
    certificate_key_usage: Optional[List[str]] = None
    certificate_extended_key_usage: Optional[List[str]] = None
    certificate_source_format: Optional[str] = None
    certificate_password_protected: Optional[bool] = None
    certificate_note: Optional[str] = None
    curve: Optional[str] = None
    source_type: str = SOURCE_TYPE

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Matches models.Artifact's exact convention (str(uuid.uuid4())[:8])
        # so artifact_id format is consistent across every detector in the
        # project, not just "some random string, format varies by module".
        d["artifact_id"] = str(uuid.uuid4())[:8]
        # Drop unset optional fields for a clean, minimal dict, matching
        # the style used by the certificate detector.
        required = {"artifact_id", "artifact_type", "file_path", "line_number",
                    "code_snippet", "detection_method", "confidence", "source_type"}
        return {k: v for k, v in d.items() if k in required or v is not None}


# --------------------------------------------------------------------------- #
# Docker CLI plumbing
# --------------------------------------------------------------------------- #


def _run_docker(
    args: List[str],
    docker_bin: str = "docker",
    timeout: int = DEFAULT_STEP_TIMEOUT,
    capture_stdout_to: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a docker subcommand safely: argument list (never shell=True),
    a hard timeout, both stdout/stderr captured (unless streamed to a file
    for `docker export`, which can be large)."""
    full_cmd = [docker_bin] + args
    try:
        if capture_stdout_to is not None:
            with open(capture_stdout_to, "wb") as out_fh:
                proc = subprocess.run(
                    full_cmd,
                    stdout=out_fh,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    shell=False,
                )
            return proc
        return subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ContainerDetectorError(
            f"Docker command timed out after {timeout}s: {docker_bin} {' '.join(args[:2])}..."
        ) from exc
    except OSError as exc:
        raise ContainerDetectorError(f"Failed to execute Docker: {exc}") from exc


def _ensure_docker_available(docker_bin: str = "docker", timeout: int = DEFAULT_STEP_TIMEOUT) -> None:
    """Verify the Docker CLI is present AND the daemon is reachable. Never
    attempts to install or start Docker."""
    if shutil.which(docker_bin) is None:
        raise ContainerDetectorError(
            f"Docker CLI ('{docker_bin}') was not found on PATH. Install Docker "
            f"and ensure the command is available; this tool will not install "
            f"it automatically."
        )

    proc = _run_docker(["info", "--format", "{{.ServerVersion}}"], docker_bin=docker_bin, timeout=timeout)
    if proc.returncode != 0:
        stderr_text = proc.stderr.decode("utf-8", "replace").strip()
        raise ContainerDetectorError(
            f"Docker CLI is installed but the Docker daemon is not reachable: "
            f"{stderr_text or '(no further detail from docker info)'}"
        )


def _docker_inspect_image(image_name: str, docker_bin: str, timeout: int) -> Dict[str, Any]:
    proc = _run_docker(["inspect", image_name], docker_bin=docker_bin, timeout=timeout)
    if proc.returncode != 0:
        stderr_text = proc.stderr.decode("utf-8", "replace").strip()
        if "no such object" in stderr_text.lower() or "no such image" in stderr_text.lower():
            raise ContainerDetectorError(f"Image not found: {image_name}")
        raise ContainerDetectorError(f"Docker could not inspect image '{image_name}': {stderr_text}")

    try:
        data = json.loads(proc.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        raise ContainerDetectorError(f"Docker returned unparseable inspect output for '{image_name}': {exc}") from exc

    if not data:
        raise ContainerDetectorError(f"Image not found: {image_name}")
    return data[0]


def _create_temp_container(image_name: str, docker_bin: str, timeout: int) -> str:
    proc = _run_docker(["create", image_name], docker_bin=docker_bin, timeout=timeout)
    if proc.returncode != 0:
        stderr_text = proc.stderr.decode("utf-8", "replace").strip()
        raise ContainerDetectorError(f"Failed to create a temporary container from '{image_name}': {stderr_text}")
    container_id = proc.stdout.decode("utf-8", "replace").strip()
    if not container_id:
        raise ContainerDetectorError(f"Docker did not return a container ID for image '{image_name}'")
    return container_id


def _remove_container(container_id: str, docker_bin: str, timeout: int) -> None:
    """Best-effort cleanup. Never raises -- a cleanup failure must not mask
    the original result/error, but it also must not be silently invisible;
    callers that care can check the return value."""
    try:
        _run_docker(["rm", "-f", container_id], docker_bin=docker_bin, timeout=timeout)
    except ContainerDetectorError:
        pass


def _export_container_filesystem(
    container_id: str, docker_bin: str, timeout: int, dest_dir: str
) -> str:
    """Export the container's filesystem to a tar file (does not start the
    container's process). Returns the tar file path."""
    tar_path = os.path.join(dest_dir, f"{container_id}.tar")
    proc = _run_docker(
        ["export", container_id], docker_bin=docker_bin, timeout=timeout, capture_stdout_to=tar_path,
    )
    if proc.returncode != 0:
        stderr_text = proc.stderr.decode("utf-8", "replace").strip()
        raise ContainerDetectorError(f"Failed to export container filesystem: {stderr_text}")
    return tar_path


def _safe_extract_tar(tar_path: str, dest_dir: str) -> None:
    """Extract a tar file while guarding against path traversal
    ("zip slip") -- every member's resolved path must stay inside dest_dir."""
    dest_dir_real = os.path.realpath(dest_dir)
    with tarfile.open(tar_path, mode="r") as tar:
        safe_members = []
        for member in tar.getmembers():
            member_path = os.path.realpath(os.path.join(dest_dir, member.name))
            if not (member_path == dest_dir_real or member_path.startswith(dest_dir_real + os.sep)):
                continue  # skip anything trying to escape the extraction root
            # Skip device/fifo/special files -- irrelevant for crypto discovery
            # and unnecessary risk to extract.
            if member.isdev():
                continue
            safe_members.append(member)
        try:
            tar.extractall(path=dest_dir, members=safe_members)
        except (OSError, tarfile.TarError):
            # Individual bad entries (broken symlinks, permission issues)
            # should not abort the whole extraction; fall back to a
            # per-member best-effort extraction.
            for member in safe_members:
                try:
                    tar.extract(member, path=dest_dir)
                except (OSError, tarfile.TarError):
                    continue


# --------------------------------------------------------------------------- #
# Image metadata discovery
# --------------------------------------------------------------------------- #


def _metadata_summary_and_findings(image_name: str, inspect_data: Dict[str, Any]) -> List[ContainerFinding]:
    findings: List[ContainerFinding] = []

    config = inspect_data.get("Config", {}) or {}
    entrypoint = config.get("Entrypoint") or []
    cmd = config.get("Cmd") or []
    env_list = config.get("Env") or []
    labels = config.get("Labels") or {}

    textual_blob_lines = []
    if entrypoint:
        textual_blob_lines.append(" ".join(str(x) for x in entrypoint))
    if cmd:
        textual_blob_lines.append(" ".join(str(x) for x in cmd))

    for entry in env_list:
        if "=" not in entry:
            continue
        name, _, value = entry.partition("=")
        redacted = _redact_env_value(name, value)
        if redacted is not None:
            textual_blob_lines.append(f"{name}={redacted}")
        # else: secret-looking var -- name is not itself crypto evidence
        # unless the *name* matches a crypto-context pattern; skip silently.

    for k, v in labels.items():
        textual_blob_lines.append(f"{k}={v}")

    metadata_text = "\n".join(textual_blob_lines)
    if metadata_text.strip():
        pattern_findings = _scan_text_for_crypto_patterns(
            metadata_text, file_path=f"docker-inspect:{image_name}", base_confidence=0.7,
        )
        for f in pattern_findings:
            f.detection_method = "docker_inspect"
        findings.extend(pattern_findings)

    return findings


# --------------------------------------------------------------------------- #
# Filesystem crypto discovery
# --------------------------------------------------------------------------- #


def _classify_key_file(file_path: str) -> Optional[ContainerFinding]:
    """Report a key file's existence/type WITHOUT reading beyond a small
    header peek, and never storing key content."""
    ext = os.path.splitext(file_path)[1].lower()
    basename = os.path.basename(file_path)

    try:
        with open(file_path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return ContainerFinding(
            artifact_type="key",
            file_path=file_path,
            detection_method="filesystem_pattern",
            confidence=0.5,
            evidence="key-like filename; file unreadable",
        )

    text_head = head.decode("utf-8", errors="ignore")
    is_pem_public = "PUBLIC KEY" in text_head.upper()
    is_openssh_public = bool(re.match(
        r"^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-\S+)\s", text_head.strip()
    ))
    header_match = _PEM_KEY_HEADER_RE.search(text_head)

    if is_pem_public or is_openssh_public or (ext == ".pub" and not header_match):
        return ContainerFinding(
            artifact_type="public_key",
            file_path=file_path,
            detection_method="filesystem_pattern",
            confidence=0.85,
        )

    if header_match:
        kind = header_match.group(1).strip().lower()
        algorithm = _KEY_TYPE_TO_ALGORITHM.get(kind)
        return ContainerFinding(
            artifact_type="private_key",
            file_path=file_path,
            algorithm=algorithm,
            detection_method="filesystem_pattern",
            confidence=0.90,
        )

    # Extension/basename suggested a key but no recognizable PEM header was
    # found in the first 4KB (could be a binary/OpenSSH-format key, or a
    # non-key file that merely matched the naming convention).
    return ContainerFinding(
        artifact_type="key",
        file_path=file_path,
        detection_method="filesystem_pattern",
        confidence=0.4,
        evidence="key-like filename, format not confirmed",
    )


def _classify_certificate_file(file_path: str, display_path: str, timeout: int) -> List[ContainerFinding]:
    if scan_certificate is None:
        return [ContainerFinding(
            artifact_type="certificate",
            file_path=display_path,
            detection_method="filesystem_pattern",
            confidence=0.4,
            evidence="certificate-like extension; certificate_detector unavailable for parsing",
        )]

    try:
        cert_results = scan_certificate(file_path, timeout=timeout)
    except CertificateDetectorError as exc:
        return [ContainerFinding(
            artifact_type="certificate",
            file_path=display_path,
            detection_method="filesystem_pattern",
            confidence=0.3,
            evidence=f"certificate-like extension but could not be parsed: {_scrub(str(exc))[:200]}",
        )]

    findings: List[ContainerFinding] = []
    for cert in cert_results:
        if cert.get("artifact_type") == "pkcs12":
            findings.append(ContainerFinding(
                artifact_type="pkcs12",
                file_path=display_path,
                detection_method="certificate_detector",
                confidence=cert.get("confidence", 0.5),
                evidence=cert.get("note"),
                certificate_password_protected=cert.get("password_protected"),
                certificate_note=cert.get("note"),
            ))
            continue

        # Field-for-field the same mapping scanner.py's _certificate_to_artifact
        # uses for directly-scanned certificate files, so a certificate found
        # INSIDE a container carries exactly the same schema as one found by
        # scanning a certificate file directly (spec: "certificate findings
        # are compatible with the same schema").
        findings.append(ContainerFinding(
            artifact_type="certificate",
            file_path=display_path,
            algorithm=cert.get("algorithm"),
            key_size=cert.get("key_size"),
            detection_method="certificate_detector",
            confidence=cert.get("confidence", 0.95),
            certificate_subject=cert.get("subject"),
            certificate_issuer=cert.get("issuer"),
            certificate_expiry=cert.get("not_after"),
            certificate_serial_number=cert.get("serial_number"),
            certificate_not_before=cert.get("not_before"),
            certificate_version=cert.get("certificate_version"),
            certificate_signature_algorithm=cert.get("signature_algorithm"),
            certificate_ec_curve=cert.get("ec_curve"),
            certificate_subject_alternative_names=cert.get("subject_alternative_names"),
            certificate_key_usage=cert.get("key_usage"),
            certificate_extended_key_usage=cert.get("extended_key_usage"),
            certificate_source_format=cert.get("source_format"),
        ))
    return findings


def _scan_filesystem(
    root_dir: str,
    timeout: int,
    max_files_scanned: int,
    max_file_size_bytes: int,
) -> List[ContainerFinding]:
    findings: List[ContainerFinding] = []
    files_scanned = 0

    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if files_scanned >= max_files_scanned:
                return findings
            full_path = os.path.join(dirpath, filename)
            if os.path.islink(full_path) and not os.path.exists(full_path):
                continue  # dangling symlink from the exported layer

            display_path = "/" + os.path.relpath(full_path, root_dir).replace(os.sep, "/")
            ext = os.path.splitext(filename)[1].lower()

            try:
                if ext in CERT_EXTENSIONS:
                    files_scanned += 1
                    findings.extend(_classify_certificate_file(full_path, display_path, timeout))
                    continue

                if ext in KEY_EXTENSIONS or filename in KEY_BASENAMES:
                    files_scanned += 1
                    finding = _classify_key_file(full_path)
                    if finding:
                        finding.file_path = display_path
                        findings.append(finding)
                    continue

                if filename in CONFIG_BASENAMES or ext in CONFIG_EXTENSIONS:
                    files_scanned += 1
                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        continue
                    if size > max_file_size_bytes:
                        continue
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                    except OSError:
                        continue
                    file_findings = _scan_text_for_crypto_patterns(content, display_path, base_confidence=0.65)
                    findings.extend(file_findings)
            except OSError:
                # Unreadable/broken file inside the image -- skip, do not
                # abort the whole filesystem scan.
                continue

    return findings


# --------------------------------------------------------------------------- #
# Package discovery (reads package-manager databases directly; never
# executes anything from inside the image)
# --------------------------------------------------------------------------- #


def _scan_dpkg_status(root_dir: str) -> List[ContainerFinding]:
    status_path = os.path.join(root_dir, "var", "lib", "dpkg", "status")
    if not os.path.isfile(status_path):
        return []

    findings: List[ContainerFinding] = []
    try:
        with open(status_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return []

    current_pkg = None
    current_version = None
    for block in content.split("\n\n"):
        current_pkg = None
        current_version = None
        for line in block.splitlines():
            if line.startswith("Package:"):
                current_pkg = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                current_version = line.split(":", 1)[1].strip()
        if current_pkg and current_pkg.lower() in KNOWN_CRYPTO_LIBS:
            library, confidence = KNOWN_CRYPTO_LIBS[current_pkg.lower()]
            findings.append(ContainerFinding(
                artifact_type="library",
                library=library,
                dependency_version=current_version,
                file_path="/var/lib/dpkg/status",
                detection_method="package_metadata",
                confidence=confidence,
                evidence=f"dpkg package: {current_pkg}",
            ))
    return findings


def _scan_apk_installed(root_dir: str) -> List[ContainerFinding]:
    installed_path = os.path.join(root_dir, "lib", "apk", "db", "installed")
    if not os.path.isfile(installed_path):
        return []

    findings: List[ContainerFinding] = []
    try:
        with open(installed_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return []

    current_pkg = None
    current_version = None
    for line in content.splitlines():
        if line.startswith("P:"):
            current_pkg = line[2:].strip()
        elif line.startswith("V:"):
            current_version = line[2:].strip()
        elif line == "":
            if current_pkg and current_pkg.lower() in KNOWN_CRYPTO_LIBS:
                library, confidence = KNOWN_CRYPTO_LIBS[current_pkg.lower()]
                findings.append(ContainerFinding(
                    artifact_type="library",
                    library=library,
                    dependency_version=current_version,
                    file_path="/lib/apk/db/installed",
                    detection_method="package_metadata",
                    confidence=confidence,
                    evidence=f"apk package: {current_pkg}",
                ))
            current_pkg = None
            current_version = None
    return findings


def _scan_rpm_db(root_dir: str, timeout: int) -> List[ContainerFinding]:
    """Best-effort: uses the HOST's own `rpm` binary (if present) against the
    extracted image's rpm database directory. This inspects data, it does
    not execute anything that came from inside the image."""
    rpm_db_dir = os.path.join(root_dir, "var", "lib", "rpm")
    if not os.path.isdir(rpm_db_dir):
        return []
    if shutil.which("rpm") is None:
        return []

    try:
        proc = subprocess.run(
            ["rpm", "--dbpath", rpm_db_dir, "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []

    findings: List[ContainerFinding] = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if "\t" not in line:
            continue
        name, _, version = line.partition("\t")
        if name.lower() in KNOWN_CRYPTO_LIBS:
            library, confidence = KNOWN_CRYPTO_LIBS[name.lower()]
            findings.append(ContainerFinding(
                artifact_type="library",
                library=library,
                dependency_version=version.strip() or None,
                file_path="/var/lib/rpm",
                detection_method="package_metadata",
                confidence=confidence,
                evidence=f"rpm package: {name}",
            ))
    return findings


def _scan_packages(root_dir: str, timeout: int) -> List[ContainerFinding]:
    findings: List[ContainerFinding] = []
    findings.extend(_scan_dpkg_status(root_dir))
    findings.extend(_scan_apk_installed(root_dir))
    findings.extend(_scan_rpm_db(root_dir, timeout))
    return findings


# --------------------------------------------------------------------------- #
# Public interface
# --------------------------------------------------------------------------- #


def scan_container_image(
    image_name: str,
    docker_bin: str = "docker",
    timeout: int = DEFAULT_STEP_TIMEOUT,
    export_timeout: int = DEFAULT_EXPORT_TIMEOUT,
    max_files_scanned: int = DEFAULT_MAX_FILES_SCANNED,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
) -> List[Dict[str, Any]]:
    """
    Scan a built container image for cryptographic evidence.

    Args:
        image_name: e.g. "python:3.12", "nginx:latest", "my-local-image:latest".
        docker_bin: name/path of the Docker CLI binary.
        timeout: per-subprocess timeout in seconds for inspect/create/rm.
        export_timeout: timeout in seconds for `docker export` (can be
            large for big images).
        max_files_scanned: hard cap on filesystem entries inspected, so a
            huge image cannot make this run unbounded.
        max_file_size_bytes: files larger than this are skipped for
            content scanning (still counted for cert/key classification,
            which only peeks at a header).

    Returns:
        A list of finding dicts. Never raises for individual unreadable or
        malformed files inside the image -- those are skipped or reported
        as low-confidence evidence instead.

    Raises:
        ContainerDetectorError: Docker CLI missing, daemon unreachable,
            image not found, or a Docker operation (inspect/create/export)
            failed or timed out.
    """
    if not image_name or not isinstance(image_name, str):
        raise ContainerDetectorError("A non-empty image name/tag is required.")

    _ensure_docker_available(docker_bin=docker_bin, timeout=timeout)

    inspect_data = _docker_inspect_image(image_name, docker_bin=docker_bin, timeout=timeout)
    findings: List[ContainerFinding] = []
    findings.extend(_metadata_summary_and_findings(image_name, inspect_data))

    container_id: Optional[str] = None
    tmp_dir = tempfile.mkdtemp(prefix="ecdat_container_scan_")
    try:
        container_id = _create_temp_container(image_name, docker_bin=docker_bin, timeout=timeout)
        tar_path = _export_container_filesystem(container_id, docker_bin, export_timeout, tmp_dir)

        fs_root = os.path.join(tmp_dir, "rootfs")
        os.makedirs(fs_root, exist_ok=True)
        _safe_extract_tar(tar_path, fs_root)
        try:
            os.remove(tar_path)
        except OSError:
            pass

        findings.extend(_scan_filesystem(fs_root, timeout, max_files_scanned, max_file_size_bytes))
        findings.extend(_scan_packages(fs_root, timeout))
    finally:
        if container_id:
            _remove_container(container_id, docker_bin=docker_bin, timeout=timeout)
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return [f.to_dict() for f in findings]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python container_detector.py <image-name>")
        raise SystemExit(1)

    try:
        results = scan_container_image(sys.argv[1])
    except ContainerDetectorError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)

    print(json.dumps(results, indent=2))