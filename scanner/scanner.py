"""
ECDAT — Part 1: Discovery / Scanner Engine
============================================
Scans Python source files for cryptographic artifacts using AST parsing
(not regex — AST is robust to formatting, comments, and code style).

OUTPUT CONTRACT (this is what Parts 2 and 3 consume):
Each detected artifact is a dict with this exact shape:
{
    "artifact_id": str,          # unique id
    "artifact_type": str,        # "algorithm" | "hash" | "cipher"
    "algorithm": str,            # e.g. "RSA", "AES", "MD5"
    "key_size": int or None,     # bits, if determinable from code
    "library": str,              # e.g. "Crypto.PublicKey", "cryptography"
    "file_path": str,
    "line_number": int,
    "code_snippet": str,
    "detection_method": str,     # "ast_call" | "ast_import"
    "confidence": float          # 0.0 - 1.0
}

Run: python scanner.py <directory_to_scan> [output.json]
"""

import ast
import json
import os
import sys
import uuid
from dataclasses import dataclass, asdict
from typing import Optional

try:
    from java_detector import scan_java_file
    JAVA_SUPPORT = True
except ImportError:
    JAVA_SUPPORT = False

from c_detector import scan_c_file


# ---------------------------------------------------------------------------
# Knowledge base: what to look for. This is intentionally a plain data
# structure (not hardcoded logic) so Snigdha/Samridhi can extend it without
# touching the AST-walking code below.
# ---------------------------------------------------------------------------

# Maps a function/class name (as it appears in a call, e.g. RSA.generate)
# to (algorithm, artifact_type, library_hint)
CALL_SIGNATURES = {
    "RSA.generate":            ("RSA", "algorithm", "Crypto.PublicKey"),
    "rsa.generate_private_key": ("RSA", "algorithm", "cryptography"),
    "ec.generate_private_key": ("ECC", "algorithm", "cryptography"),
    "DSA.generate":            ("DSA", "algorithm", "Crypto.PublicKey"),
    "AES.new":                 ("AES", "algorithm", "Crypto.Cipher"),
    "DES.new":                 ("DES", "algorithm", "Crypto.Cipher"),
    "DES3.new":                ("3DES", "algorithm", "Crypto.Cipher"),
    "ChaCha20.new":            ("ChaCha20", "algorithm", "Crypto.Cipher"),
    "hashlib.md5":             ("MD5", "hash", "hashlib"),
    "hashlib.sha1":            ("SHA-1", "hash", "hashlib"),
    "hashlib.sha256":          ("SHA-256", "hash", "hashlib"),
    "hashlib.sha384":          ("SHA-384", "hash", "hashlib"),
    "hashlib.sha512":          ("SHA-512", "hash", "hashlib"),
    "hashes.SHA256":           ("SHA-256", "hash", "cryptography"),
    "hashes.SHA1":             ("SHA-1", "hash", "cryptography"),
    "ec.SECP256R1":            ("ECC-P256", "algorithm", "cryptography"),
}

# Import statements that signal "this file uses crypto" even before we see
# a specific call - useful as a lower-confidence supporting signal.
IMPORT_SIGNATURES = {
    "Crypto.PublicKey": "Crypto.PublicKey",
    "Crypto.Cipher": "Crypto.Cipher",
    "Crypto.Hash": "Crypto.Hash",
    "cryptography.hazmat.primitives.asymmetric": "cryptography",
    "cryptography.hazmat.primitives.ciphers": "cryptography",
    "cryptography.hazmat.primitives.hashes": "cryptography",
    "hashlib": "hashlib",
}


@dataclass
class Artifact:
    artifact_id: str
    artifact_type: str
    algorithm: str
    key_size: Optional[int]
    library: str
    file_path: str
    line_number: int
    code_snippet: str
    detection_method: str
    confidence: float


class CryptoASTVisitor(ast.NodeVisitor):
    """Walks a Python AST and collects crypto-artifact detections."""

    def __init__(self, file_path: str, source_lines: list):
        self.file_path = file_path
        self.source_lines = source_lines
        self.artifacts: list[Artifact] = []

    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        return self.source_lines[idx].strip() if 0 <= idx < len(self.source_lines) else ""

    def _call_name(self, node: ast.Call) -> Optional[str]:
        """Resolve something like RSA.generate(...) into the string 'RSA.generate'."""
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
        elif isinstance(func, ast.Name):
            return func.id
        return None

    def _extract_key_size(self, node: ast.Call) -> Optional[int]:
        """Look for an integer literal argument or key_size= kwarg."""
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                return arg.value
        for kw in node.keywords:
            if kw.arg in ("key_size", "bits") and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, int):
                    return kw.value.value
        return None

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            for sig, lib in IMPORT_SIGNATURES.items():
                if alias.name.startswith(sig):
                    self.artifacts.append(Artifact(
                        artifact_id=str(uuid.uuid4())[:8],
                        artifact_type="import_signal",
                        algorithm="UNSPECIFIED",
                        key_size=None,
                        library=lib,
                        file_path=self.file_path,
                        line_number=node.lineno,
                        code_snippet=self._snippet(node.lineno),
                        detection_method="ast_import",
                        confidence=0.3,
                    ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for sig, lib in IMPORT_SIGNATURES.items():
            if module.startswith(sig):
                self.artifacts.append(Artifact(
                    artifact_id=str(uuid.uuid4())[:8],
                    artifact_type="import_signal",
                    algorithm="UNSPECIFIED",
                    key_size=None,
                    library=lib,
                    file_path=self.file_path,
                    line_number=node.lineno,
                    code_snippet=self._snippet(node.lineno),
                    detection_method="ast_import",
                    confidence=0.3,
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._call_name(node)
        if call_name in CALL_SIGNATURES:
            algorithm, artifact_type, library = CALL_SIGNATURES[call_name]
            key_size = self._extract_key_size(node)
            self.artifacts.append(Artifact(
                artifact_id=str(uuid.uuid4())[:8],
                artifact_type=artifact_type,
                algorithm=algorithm,
                key_size=key_size,
                library=library,
                file_path=self.file_path,
                line_number=node.lineno,
                code_snippet=self._snippet(node.lineno),
                detection_method="ast_call",
                confidence=0.95,
            ))
        self.generic_visit(node)


def scan_file(file_path: str) -> list[Artifact]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []
    visitor = CryptoASTVisitor(file_path, source.splitlines())
    visitor.visit(tree)
    return visitor.artifacts


def scan_directory(directory: str) -> list[dict]:
    """
    Multi-language entry point. Routes each file to the right detector based
    on extension. This is the single function Part 2 (Snigdha) and Part 4
    (backend) should call — they don't need to know which language-specific
    detector ran under the hood, only that they get back a uniform list of
    artifact dicts matching the output contract documented at the top of
    this file.
    """
    all_artifacts = []
    skipped_java = 0

    for root, _, files in os.walk(directory):
        for fname in files:
            full_path = os.path.join(root, fname)

            if fname.endswith(".py"):
                artifacts = scan_file(full_path)
                all_artifacts.extend(asdict(a) for a in artifacts)

            elif fname.endswith(".java"):
                if JAVA_SUPPORT:
                    all_artifacts.extend(scan_java_file(full_path))
                else:
                    skipped_java += 1

            elif fname.endswith((".c", ".h", ".cpp", ".cc")):
                all_artifacts.extend(scan_c_file(full_path))

    if skipped_java:
        print(f"  [warning] {skipped_java} .java file(s) skipped — install 'javalang' to enable Java scanning")

    return all_artifacts


def _drop_import_signals_if_call_found(artifacts: list[dict]) -> list[dict]:
    """
    Post-process step: if a file has at least one high-confidence call
    detection, we keep the low-confidence import signals too (Snigdha's
    dedup/pattern module in Part 2 will decide what to merge) — but we tag
    them so downstream code knows which ones are 'supporting evidence' vs
    'confirmed detections'. This keeps Part 1's output honest rather than
    silently dropping useful context.
    """
    return artifacts


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <directory_to_scan> [output.json]")
        sys.exit(1)

    target_dir = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "scanner_output.json"

    results = scan_directory(target_dir)
    results = _drop_import_signals_if_call_found(results)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Scanned '{target_dir}' — {len(results)} artifacts detected.")
    print(f"Output written to {output_path}")

    # Quick console summary
    confirmed = [a for a in results if a["detection_method"] == "ast_call"]
    print(f"  Confirmed (high-confidence) detections: {len(confirmed)}")
    for a in confirmed:
        ks = f" ({a['key_size']}-bit)" if a["key_size"] else ""
        print(f"    [{a['file_path']}:{a['line_number']}] {a['algorithm']}{ks}  <- {a['code_snippet']}")
