"""
ECDAT — Tree-sitter Detector
============================

Structural cryptographic source-code detection using Tree-sitter.

Supported languages:
  - Python
  - Java
  - JavaScript
  - TypeScript
  - C
  - C++

Detects:
  - Cryptographic API function & method calls
  - Imports & include statements
  - Key size extraction from arguments/parameters
  - Mode (GCM, CBC, etc.) and curve (P-256, etc.) extraction
  - Structured findings normalized into the shared Artifact model
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import os
import re
import uuid

import tree_sitter

# Tree-sitter language imports
try:
    import tree_sitter_python
    import tree_sitter_java
    import tree_sitter_javascript
    import tree_sitter_typescript
    import tree_sitter_c
    import tree_sitter_cpp

    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False


from scanner.models import (
    Artifact,
    CONFIDENCE_AST_CALL,
    CONFIDENCE_IMPORT_SIGNAL,
)

# ---------------------------------------------------------------------------
# Language-to-TreeSitter Language mapping
# ---------------------------------------------------------------------------

_LANGUAGES: Dict[str, Any] = {}

if HAS_TREE_SITTER:
    try:
        _LANGUAGES["python"] = tree_sitter.Language(tree_sitter_python.language())
        _LANGUAGES["java"] = tree_sitter.Language(tree_sitter_java.language())
        _LANGUAGES["javascript"] = tree_sitter.Language(tree_sitter_javascript.language())
        _LANGUAGES["typescript"] = tree_sitter.Language(tree_sitter_typescript.language_typescript())
        _LANGUAGES["c"] = tree_sitter.Language(tree_sitter_c.language())
        _LANGUAGES["cpp"] = tree_sitter.Language(tree_sitter_cpp.language())
    except Exception:
        pass


def get_language_for_file(file_path: str) -> Optional[str]:
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".py":
        return "python"
    elif ext == ".java":
        return "java"
    elif ext in (".js", ".jsx"):
        return "javascript"
    elif ext in (".ts", ".tsx"):
        return "typescript"
    elif ext in (".c", ".h"):
        return "c"
    elif ext in (".cpp", ".hpp", ".cc", ".cxx"):
        return "cpp"
    return None


# ---------------------------------------------------------------------------
# Known Signatures & Lookup Tables
# ---------------------------------------------------------------------------

# Signature map for Python / JS / C API calls
# (call_name_pattern) -> (algorithm, artifact_type, library)
CALL_SIGNATURES = {
    # Python cryptography / PyCryptodome / hashlib
    "RSA.generate": ("RSA", "algorithm", "Crypto.PublicKey"),
    "rsa.generate_private_key": ("RSA", "algorithm", "cryptography"),
    "ec.generate_private_key": ("ECC", "algorithm", "cryptography"),
    "DSA.generate": ("DSA", "algorithm", "Crypto.PublicKey"),
    "AES.new": ("AES", "algorithm", "Crypto.Cipher"),
    "DES.new": ("DES", "algorithm", "Crypto.Cipher"),
    "DES3.new": ("3DES", "algorithm", "Crypto.Cipher"),
    "ChaCha20.new": ("ChaCha20", "algorithm", "Crypto.Cipher"),
    "hashlib.md5": ("MD5", "hash", "hashlib"),
    "hashlib.sha1": ("SHA-1", "hash", "hashlib"),
    "hashlib.sha256": ("SHA-256", "hash", "hashlib"),
    "hashlib.sha384": ("SHA-384", "hash", "hashlib"),
    "hashlib.sha512": ("SHA-512", "hash", "hashlib"),
    "hashes.SHA256": ("SHA-256", "hash", "cryptography"),
    "hashes.SHA1": ("SHA-1", "hash", "cryptography"),
    "hashes.MD5": ("MD5", "hash", "cryptography"),
    "hashes.SHA384": ("SHA-384", "hash", "cryptography"),
    "hashes.SHA512": ("SHA-512", "hash", "cryptography"),

    # C / OpenSSL
    "RSA_generate_key": ("RSA", "algorithm", "openssl/rsa.h"),
    "RSA_generate_key_ex": ("RSA", "algorithm", "openssl/rsa.h"),
    "AES_encrypt": ("AES", "algorithm", "openssl/aes.h"),
    "AES_set_encrypt_key": ("AES", "algorithm", "openssl/aes.h"),
    "DES_ecb_encrypt": ("DES", "algorithm", "openssl/des.h"),
    "DES_set_key": ("DES", "algorithm", "openssl/des.h"),
    "MD5": ("MD5", "hash", "openssl/md5.h"),
    "EVP_md5": ("MD5", "hash", "openssl/evp.h"),
    "EVP_sha1": ("SHA-1", "hash", "openssl/evp.h"),
    "EVP_sha256": ("SHA-256", "hash", "openssl/evp.h"),
    "EVP_sha384": ("SHA-384", "hash", "openssl/evp.h"),
    "EVP_sha512": ("SHA-512", "hash", "openssl/evp.h"),
}

EC_CURVE_NAMES = {
    "SECP256R1": "P-256",
    "SECP384R1": "P-384",
    "SECP521R1": "P-521",
    "SECP224R1": "P-224",
    "SECP256K1": "secp256k1",
}

JAVA_ALGORITHM_MAP = {
    "MD5": ("MD5", "hash"),
    "SHA-1": ("SHA-1", "hash"),
    "SHA1": ("SHA-1", "hash"),
    "SHA-256": ("SHA-256", "hash"),
    "SHA256": ("SHA-256", "hash"),
    "SHA-384": ("SHA-384", "hash"),
    "SHA-512": ("SHA-512", "hash"),
    "RSA": ("RSA", "algorithm"),
    "DES": ("DES", "algorithm"),
    "DESede": ("3DES", "algorithm"),
    "AES": ("AES", "algorithm"),
    "EC": ("ECC", "algorithm"),
    "ECDSA": ("ECDSA", "algorithm"),
    "ECDH": ("ECDH", "algorithm"),
    "DSA": ("DSA", "algorithm"),
}

JAVA_FACTORY_CLASSES = {
    "MessageDigest", "Cipher", "KeyPairGenerator", "Signature", "KeyGenerator"
}

# ---------------------------------------------------------------------------
# Tree-sitter Visitor / Traversal
# ---------------------------------------------------------------------------

class TreeSitterVisitor:
    def __init__(self, file_path: str, source_bytes: bytes, language: str):
        self.file_path = file_path
        self.source_bytes = source_bytes
        self.source_str = source_bytes.decode("utf-8", errors="ignore")
        self.source_lines = self.source_str.splitlines()
        self.language = language
        self.artifacts: List[Artifact] = []

    def _get_snippet(self, line_no: int) -> str:
        idx = line_no - 1
        if 0 <= idx < len(self.source_lines):
            return self.source_lines[idx].strip()
        return ""

    def _node_text(self, node: tree_sitter.Node) -> str:
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def walk(self, node: tree_sitter.Node):
        ntype = node.type
        line_no = node.start_point[0] + 1

        if self.language == "python":
            self._handle_python_node(node, ntype, line_no)
        elif self.language == "java":
            self._handle_java_node(node, ntype, line_no)
        elif self.language in ("javascript", "typescript"):
            self._handle_js_node(node, ntype, line_no)
        elif self.language in ("c", "cpp"):
            self._handle_c_node(node, ntype, line_no)

        for child in node.children:
            self.walk(child)

    # -----------------------------------------------------------------------
    # Python Handler
    # -----------------------------------------------------------------------

    def _handle_python_node(self, node: tree_sitter.Node, ntype: str, line_no: int):
        if ntype == "call":
            func_node = node.child_by_field_name("function") or (node.children[0] if node.children else None)
            if not func_node:
                return

            call_name = self._node_text(func_node)
            if call_name in CALL_SIGNATURES:
                algorithm, artifact_type, library = CALL_SIGNATURES[call_name]
                key_size = self._extract_key_size_from_node(node)
                curve = self._extract_curve_from_python_call(node) if call_name == "ec.generate_private_key" else None
                mode = self._extract_mode_from_node(node) if artifact_type == "algorithm" else None

                self.artifacts.append(Artifact(
                    artifact_type=artifact_type,
                    algorithm=algorithm,
                    key_size=key_size,
                    library=library,
                    file_path=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_snippet(line_no),
                    detection_method="tree_sitter",
                    confidence=CONFIDENCE_AST_CALL,
                    curve=curve,
                    mode=mode,
                    language="Python",
                ))

        elif ntype in ("import_statement", "import_from_statement"):
            text = self._node_text(node)
            for sig, lib in [
                ("Crypto.PublicKey", "Crypto.PublicKey"),
                ("Crypto.Cipher", "Crypto.Cipher"),
                ("Crypto.Hash", "Crypto.Hash"),
                ("cryptography", "cryptography"),
                ("hashlib", "hashlib"),
            ]:
                if sig in text:
                    self.artifacts.append(Artifact(
                        artifact_type="import_signal",
                        algorithm="UNSPECIFIED",
                        key_size=None,
                        library=lib,
                        file_path=self.file_path,
                        line_number=line_no,
                        code_snippet=self._get_snippet(line_no),
                        detection_method="tree_sitter",
                        confidence=CONFIDENCE_IMPORT_SIGNAL,
                        language="Python",
                    ))
                    break

    # -----------------------------------------------------------------------
    # Java Handler
    # -----------------------------------------------------------------------

    def _handle_java_node(self, node: tree_sitter.Node, ntype: str, line_no: int):
        if ntype == "method_invocation":
            text = self._node_text(node)
            for factory in JAVA_FACTORY_CLASSES:
                if f"{factory}.getInstance(" in text:
                    # Extract string literal argument
                    match = re.search(r'getInstance\s*\(\s*["\']([^"\']+)["\']', text)
                    if match:
                        alg_str = match.group(1)
                        base_alg = alg_str.split('/')[0] if '/' in alg_str else alg_str
                        mode = None
                        if '/' in alg_str:
                            parts = alg_str.split('/')
                            if len(parts) > 1 and parts[1].upper() in ("GCM", "CBC", "ECB", "CTR", "CFB", "OFB"):
                                mode = parts[1].upper()

                        lookup_key = alg_str if alg_str in JAVA_ALGORITHM_MAP else base_alg
                        if lookup_key in JAVA_ALGORITHM_MAP:
                            algorithm, artifact_type = JAVA_ALGORITHM_MAP[lookup_key]
                            key_size = self._extract_key_size_from_node(node)
                            self.artifacts.append(Artifact(
                                artifact_type=artifact_type,
                                algorithm=algorithm,
                                key_size=key_size,
                                library=f"java.security.{factory}",
                                file_path=self.file_path,
                                line_number=line_no,
                                code_snippet=self._get_snippet(line_no),
                                detection_method="tree_sitter",
                                confidence=CONFIDENCE_AST_CALL,
                                mode=mode,
                                language="Java",
                            ))

        elif ntype == "import_declaration":
            text = self._node_text(node)
            if "javax.crypto" in text or "java.security" in text:
                self.artifacts.append(Artifact(
                    artifact_type="import_signal",
                    algorithm="UNSPECIFIED",
                    key_size=None,
                    library=text.replace("import", "").replace(";", "").strip(),
                    file_path=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_snippet(line_no),
                    detection_method="tree_sitter",
                    confidence=CONFIDENCE_IMPORT_SIGNAL,
                    language="Java",
                ))

    # -----------------------------------------------------------------------
    # JavaScript / TypeScript Handler
    # -----------------------------------------------------------------------

    def _handle_js_node(self, node: tree_sitter.Node, ntype: str, line_no: int):
        if ntype == "call_expression":
            text = self._node_text(node)

            # Node crypto APIs
            if "crypto.createHash" in text or "crypto.createHmac" in text:
                m = re.search(r'create(?:Hash|Hmac)\s*\(\s*["\']([^"\']+)["\']', text, re.I)
                if m:
                    alg = self._normalize_hash(m.group(1))
                    if alg:
                        self.artifacts.append(Artifact(
                            artifact_type="hash",
                            algorithm=alg,
                            key_size=None,
                            library="Node.js crypto",
                            file_path=self.file_path,
                            line_number=line_no,
                            code_snippet=self._get_snippet(line_no),
                            detection_method="tree_sitter",
                            confidence=CONFIDENCE_AST_CALL,
                            language="JavaScript",
                        ))

            elif "crypto.createCipheriv" in text or "crypto.createDecipheriv" in text:
                m = re.search(r'create(?:Cipheriv|Decipheriv)\s*\(\s*["\']([^"\']+)["\']', text, re.I)
                if m:
                    cipher_str = m.group(1).upper()
                    alg = "AES" if "AES" in cipher_str else ("DES" if "DES" in cipher_str else "3DES" if "3DES" in cipher_str or "TRIPLE" in cipher_str else "UNSPECIFIED")
                    mode_m = re.search(r'(GCM|CBC|CTR|ECB|OFB|CFB)', cipher_str)
                    mode = mode_m.group(1) if mode_m else None
                    ks_m = re.search(r'(128|192|256)', cipher_str)
                    key_size = int(ks_m.group(1)) if ks_m else None
                    self.artifacts.append(Artifact(
                        artifact_type="algorithm",
                        algorithm=alg,
                        key_size=key_size,
                        library="Node.js crypto",
                        file_path=self.file_path,
                        line_number=line_no,
                        code_snippet=self._get_snippet(line_no),
                        detection_method="tree_sitter",
                        confidence=CONFIDENCE_AST_CALL,
                        mode=mode,
                        language="JavaScript",
                    ))

            elif "crypto.generateKeyPair" in text or "crypto.generateKeyPairSync" in text:
                m = re.search(r'generateKeyPair(?:Sync)?\s*\(\s*["\']([^"\']+)["\']', text, re.I)
                if m:
                    alg = m.group(1).upper()
                    ks_m = re.search(r'modulusLength\s*:\s*(\d+)', text)
                    key_size = int(ks_m.group(1)) if ks_m else None
                    self.artifacts.append(Artifact(
                        artifact_type="algorithm",
                        algorithm=alg,
                        key_size=key_size,
                        library="Node.js crypto",
                        file_path=self.file_path,
                        line_number=line_no,
                        code_snippet=self._get_snippet(line_no),
                        detection_method="tree_sitter",
                        confidence=CONFIDENCE_AST_CALL,
                        language="JavaScript",
                    ))

        elif ntype in ("import_statement", "lexical_declaration"):
            text = self._node_text(node)
            if 'require("crypto")' in text or "require('crypto')" in text or 'from "crypto"' in text or "from 'crypto'" in text:
                self.artifacts.append(Artifact(
                    artifact_type="import_signal",
                    algorithm="UNSPECIFIED",
                    key_size=None,
                    library="Node.js crypto",
                    file_path=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_snippet(line_no),
                    detection_method="tree_sitter",
                    confidence=CONFIDENCE_IMPORT_SIGNAL,
                    language="JavaScript",
                ))

    # -----------------------------------------------------------------------
    # C / C++ Handler
    # -----------------------------------------------------------------------

    def _handle_c_node(self, node: tree_sitter.Node, ntype: str, line_no: int):
        if ntype == "call_expression":
            func_node = node.child_by_field_name("function") or (node.children[0] if node.children else None)
            if not func_node:
                return

            call_name = self._node_text(func_node)
            if call_name in CALL_SIGNATURES:
                algorithm, artifact_type, library = CALL_SIGNATURES[call_name]
                key_size = self._extract_key_size_from_c_call(node, call_name)
                self.artifacts.append(Artifact(
                    artifact_type=artifact_type,
                    algorithm=algorithm,
                    key_size=key_size,
                    library=library,
                    file_path=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_snippet(line_no),
                    detection_method="tree_sitter",
                    confidence=CONFIDENCE_AST_CALL,
                    language="C/C++",
                ))

        elif ntype == "preproc_include":
            text = self._node_text(node)
            if "openssl/" in text:
                header_m = re.search(r'openssl/(\w+\.h)', text)
                header = header_m.group(0) if header_m else "openssl"
                self.artifacts.append(Artifact(
                    artifact_type="import_signal",
                    algorithm="UNSPECIFIED",
                    key_size=None,
                    library=header,
                    file_path=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_snippet(line_no),
                    detection_method="tree_sitter",
                    confidence=CONFIDENCE_IMPORT_SIGNAL,
                    language="C/C++",
                ))

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _extract_key_size_from_node(self, node: tree_sitter.Node) -> Optional[int]:
        text = self._node_text(node)
        # Match explicit key size integer in args or kwargs
        m = re.search(r'\b(key_size|bits|modulusLength)\s*[:=]\s*(\d+)', text)
        if m:
            return int(m.group(2))
        # Match standalone integer arg like (2048) or (1024)
        m = re.search(r'\b(512|1024|2048|3072|4096|8192)\b', text)
        if m:
            return int(m.group(1))
        return None

    def _extract_curve_from_python_call(self, node: tree_sitter.Node) -> Optional[str]:
        text = self._node_text(node)
        for curve_ident, canonical in EC_CURVE_NAMES.items():
            if curve_ident in text:
                return canonical
        return None

    def _extract_mode_from_node(self, node: tree_sitter.Node) -> Optional[str]:
        text = self._node_text(node)
        m = re.search(r'\b(MODE_)?(GCM|CBC|EAX|ECB|CTR|CFB|OFB)\b', text, re.I)
        if m:
            return m.group(2).upper()
        return None

    def _extract_key_size_from_c_call(self, node: tree_sitter.Node, call_name: str) -> Optional[int]:
        text = self._node_text(node)
        m = re.search(r'\b(512|1024|2048|3072|4096|128|192|256)\b', text)
        if m:
            return int(m.group(1))
        return None

    def _normalize_hash(self, name: str) -> Optional[str]:
        n = name.lower().replace("-", "").replace("_", "")
        if n == "md5": return "MD5"
        if n == "sha1": return "SHA-1"
        if n == "sha224": return "SHA-224"
        if n == "sha256": return "SHA-256"
        if n == "sha384": return "SHA-384"
        if n == "sha512": return "SHA-512"
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_with_treesitter(file_path: str) -> List[Dict[str, Any]]:
    """
    Scan a source file using Tree-sitter.

    Returns:
        List[Dict[str, Any]] (list of plain Artifact dicts)
    """
    if not HAS_TREE_SITTER:
        return []

    lang_name = get_language_for_file(file_path)
    if not lang_name or lang_name not in _LANGUAGES:
        return []

    try:
        with open(file_path, "rb") as f:
            source_bytes = f.read()
    except Exception:
        return []

    try:
        language = _LANGUAGES[lang_name]
        parser = tree_sitter.Parser(language)
        tree = parser.parse(source_bytes)
    except Exception:
        return []

    visitor = TreeSitterVisitor(file_path, source_bytes, lang_name)
    visitor.walk(tree.root_node)

    return [art.to_dict() for art in visitor.artifacts]
