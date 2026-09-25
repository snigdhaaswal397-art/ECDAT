"""
ECDAT — Protocol Detector
========================

Discovers cryptographic protocols (TLS & SSH) from source code, configuration
files, and environment definitions.

Strict False-Positive Rules:
  - Comments, documentation, README files, and plain markdown descriptions are
    EXCLUDED from protocol classification.
  - Variable names containing keywords without API/configuration evidence are
    EXCLUDED.
  - Only structured API usage, official configuration directives, cipher suite
    specifications, and protocol library bindings generate protocol findings.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import os
import re

from scanner.models import (
    Artifact,
    CONFIDENCE_CONFIG_EVIDENCE,
    CONFIDENCE_AST_CALL,
)

# ---------------------------------------------------------------------------
# TLS & SSH Patterns
# ---------------------------------------------------------------------------

TLS_VERSION_PATTERNS = [
    (r"\b(TLSv1\.3|TLSv1_3|PROTOCOL_TLSv1_3|TLS1_3_VERSION)\b", "TLS 1.3", "1.3"),
    (r"\b(TLSv1\.2|TLSv1_2|PROTOCOL_TLSv1_2|TLS1_2_VERSION)\b", "TLS 1.2", "1.2"),
    (r"\b(TLSv1\.1|TLSv1_1|PROTOCOL_TLSv1_1|TLS1_1_VERSION)\b", "TLS 1.1", "1.1"),
    (r"\b(TLSv1\.0|TLSv1_0|PROTOCOL_TLSv1|TLS1_VERSION)\b", "TLS 1.0", "1.0"),
    (r"\b(SSLv3|SSLv2)\b", "SSL", "3.0"),
]

TLS_API_PATTERNS = [
    (r"\bssl\.create_default_context\s*\(", "Python ssl", "TLS 1.2+"),
    (r"\bSSLContext\s*\(", "Standard SSLContext", None),
    (r"\bSSL_CTX_new\s*\(", "OpenSSL SSL_CTX", None),
    (r"\bSSL_CTX_set_min_proto_version\s*\(", "OpenSSL Min Version", None),
    (r"\bTLS_server_method\s*\(", "OpenSSL TLS Server", None),
    (r"\btls\.connect\s*\(", "Node.js TLS", None),
    (r"\bhttps\.createServer\s*\(", "Node.js HTTPS", None),
    (r"\bSSLSocketFactory\b", "Java SSLSocketFactory", None),
]

CIPHER_SUITE_PATTERNS = [
    (r"\bECDHE-RSA-AES128-GCM-SHA256\b", "ECDHE-RSA-AES128-GCM-SHA256", "TLS 1.2"),
    (r"\bECDHE-ECDSA-AES256-GCM-SHA384\b", "ECDHE-ECDSA-AES256-GCM-SHA384", "TLS 1.2"),
    (r"\bTLS_AES_256_GCM_SHA384\b", "TLS_AES_256_GCM_SHA384", "TLS 1.3"),
    (r"\bTLS_CHACHA20_POLY1305_SHA256\b", "TLS_CHACHA20_POLY1305_SHA256", "TLS 1.3"),
    (r"\bDHE-RSA-AES256-SHA\b", "DHE-RSA-AES256-SHA", "TLS 1.0-1.2"),
]

SSH_PATTERNS = [
    (r"\bssh-keygen\b", "SSH Key Generator", None),
    (r"\bParamiko\b|\bparamiko\.SSHClient\s*\(", "Paramiko SSH", "SSHv2"),
    (r"\bJSch\s*\(", "JSch Java SSH", "SSHv2"),
    (r"\bssh-rsa\b", "SSH RSA Algorithm", "SSHv2"),
    (r"\becdsa-sha2-nistp256\b", "SSH ECDSA Algorithm", "SSHv2"),
    (r"\bssh-ed25519\b", "SSH Ed25519 Algorithm", "SSHv2"),
    (r"\bdiffie-hellman-group14-sha1\b", "SSH DH Group 14", "SSHv2"),
]

# Config file directives
CONFIG_DIRECTIVES = [
    (r"^\s*ssl_protocols\s+([^;]+);", "nginx_ssl_protocols"),
    (r"^\s*ssl_ciphers\s+([^;]+);", "nginx_ssl_ciphers"),
    (r"^\s*SSLCipherSuite\s+(\S+)", "apache_ssl_ciphers"),
    (r"^\s*SSLProtocol\s+(.+)", "apache_ssl_protocols"),
    (r"^\s*Protocol\s+(2|1,2|2,1)\b", "sshd_protocol"),
    (r"^\s*KexAlgorithms\s+(.+)", "sshd_kex"),
    (r"^\s*Ciphers\s+(.+)", "sshd_ciphers"),
    (r"^\s*HostKeyAlgorithms\s+(.+)", "sshd_hostkeys"),
]


def _is_doc_or_comment(file_path: str, line: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    fname = os.path.basename(file_path).lower()

    if ext in (".md", ".txt", ".rst", ".doc", ".docx", ".pdf", ".html") or fname in ("readme", "license", "changelog"):
        return True

    sline = line.strip()
    if sline.startswith("#") or sline.startswith("//") or sline.startswith("/*") or sline.startswith("*"):
        return True

    return False


def scan_protocol_file(file_path: str) -> List[Dict[str, Any]]:
    artifacts: List[Dict[str, Any]] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.splitlines() if hasattr(f, "splitlines") else f.read().splitlines()
    except Exception:
        return artifacts

    for line_idx, raw_line in enumerate(lines, start=1):
        if _is_doc_or_comment(file_path, raw_line):
            continue

        line = raw_line.strip()
        if not line:
            continue

        # 1. Configuration directives (nginx, apache, sshd)
        for pattern, directive_name in CONFIG_DIRECTIVES:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                protocol_name = "TLS" if "ssl" in directive_name else "SSH"
                artifacts.append(Artifact(
                    artifact_type="protocol",
                    algorithm=None,
                    key_size=None,
                    file_path=file_path,
                    detection_method="config_directive",
                    confidence=CONFIDENCE_CONFIG_EVIDENCE,
                    protocol=protocol_name,
                    code_snippet=line,
                    line_number=line_idx,
                    evidence=f"{directive_name}: {val}",
                ).to_dict())

        # 2. TLS Version patterns
        for pattern, canon_name, version in TLS_VERSION_PATTERNS:
            if re.search(pattern, line):
                artifacts.append(Artifact(
                    artifact_type="protocol",
                    algorithm=None,
                    key_size=None,
                    file_path=file_path,
                    detection_method="api_pattern",
                    confidence=CONFIDENCE_AST_CALL,
                    protocol=canon_name,
                    dependency_version=version,
                    code_snippet=line,
                    line_number=line_idx,
                    evidence=f"TLS version specification: {canon_name}",
                ).to_dict())

        # 3. TLS API calls
        for pattern, api_lib, default_ver in TLS_API_PATTERNS:
            if re.search(pattern, line):
                artifacts.append(Artifact(
                    artifact_type="protocol",
                    algorithm=None,
                    key_size=None,
                    file_path=file_path,
                    detection_method="api_pattern",
                    confidence=CONFIDENCE_AST_CALL,
                    protocol="TLS",
                    library=api_lib,
                    dependency_version=default_ver,
                    code_snippet=line,
                    line_number=line_idx,
                    evidence=f"TLS API usage: {api_lib}",
                ).to_dict())

        # 4. Cipher Suites
        for pattern, cipher_name, tls_ver in CIPHER_SUITE_PATTERNS:
            if re.search(pattern, line):
                artifacts.append(Artifact(
                    artifact_type="protocol",
                    algorithm=cipher_name,
                    key_size=None,
                    file_path=file_path,
                    detection_method="cipher_suite",
                    confidence=CONFIDENCE_CONFIG_EVIDENCE,
                    protocol="TLS",
                    dependency_version=tls_ver,
                    code_snippet=line,
                    line_number=line_idx,
                    evidence=f"TLS Cipher Suite: {cipher_name}",
                ).to_dict())

        # 5. SSH Evidence
        for pattern, ssh_desc, ssh_ver in SSH_PATTERNS:
            if re.search(pattern, line):
                artifacts.append(Artifact(
                    artifact_type="protocol",
                    algorithm=None,
                    key_size=None,
                    file_path=file_path,
                    detection_method="ssh_evidence",
                    confidence=CONFIDENCE_CONFIG_EVIDENCE,
                    protocol="SSH",
                    dependency_version=ssh_ver,
                    code_snippet=line,
                    line_number=line_idx,
                    evidence=f"SSH evidence: {ssh_desc}",
                ).to_dict())

    return artifacts
