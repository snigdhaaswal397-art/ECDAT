"""
Unit tests for Protocol detector (TLS & SSH), including false positive prevention.
"""

import os
import tempfile
from scanner.detectors.protocol_detector import scan_protocol_file


def test_protocol_tls_detection():
    content = """
import ssl
ctx = ssl.create_default_context()
ctx.options |= ssl.PROTOCOL_TLSv1_2
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_protocol_file(f_path)
        assert len(results) > 0
        tls_finding = next((r for r in results if r.get("protocol") in ("TLS 1.2", "TLS")), None)
        assert tls_finding is not None
    finally:
        os.unlink(f_path)


def test_protocol_ssh_detection():
    content = """
import paramiko
client = paramiko.SSHClient()
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_protocol_file(f_path)
        ssh_finding = next((r for r in results if r.get("protocol") == "SSH"), None)
        assert ssh_finding is not None
    finally:
        os.unlink(f_path)


def test_protocol_false_positive_comments_docs():
    # Comments & documentation mentioning RSA/AES/TLS should NOT generate protocol findings
    content = """
# This documentation explains TLS and SSH configuration details.
// RSA key generation guide
/* AES encryption overview */
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_protocol_file(f_path)
        assert len(results) == 0
    finally:
        os.unlink(f_path)
