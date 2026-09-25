"""
Unit tests for Tree-sitter detector.
"""

import os
import tempfile
import pytest
from scanner.detectors.treesitter_detector import scan_with_treesitter, HAS_TREE_SITTER

pytestmark = pytest.mark.skipif(not HAS_TREE_SITTER, reason="tree-sitter binding not installed")


def test_treesitter_python_rsa_and_import():
    content = """
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_with_treesitter(f_path)
        assert len(results) >= 2
        # Check RSA call detection
        rsa_finding = next((r for r in results if r.get("algorithm") == "RSA"), None)
        assert rsa_finding is not None
        assert rsa_finding.get("key_size") == 2048
        assert rsa_finding.get("detection_method") == "tree_sitter"
        assert rsa_finding.get("confidence") == 0.95
    finally:
        os.unlink(f_path)


def test_treesitter_java_cipher():
    content = """
import javax.crypto.Cipher;

public class App {
    public void run() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".java", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_with_treesitter(f_path)
        aes_finding = next((r for r in results if r.get("algorithm") == "AES"), None)
        assert aes_finding is not None
        assert aes_finding.get("mode") == "GCM"
        assert aes_finding.get("detection_method") == "tree_sitter"
    finally:
        os.unlink(f_path)


def test_treesitter_js_node_crypto():
    content = """
const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_with_treesitter(f_path)
        aes_finding = next((r for r in results if r.get("algorithm") == "AES"), None)
        assert aes_finding is not None
        assert aes_finding.get("key_size") == 256
        assert aes_finding.get("mode") == "GCM"
    finally:
        os.unlink(f_path)


def test_treesitter_c_openssl():
    content = """
#include <openssl/rsa.h>

void gen() {
    RSA *key = RSA_generate_key(2048, 65537, NULL, NULL);
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_with_treesitter(f_path)
        rsa_finding = next((r for r in results if r.get("algorithm") == "RSA"), None)
        assert rsa_finding is not None
        assert rsa_finding.get("key_size") == 2048
    finally:
        os.unlink(f_path)
