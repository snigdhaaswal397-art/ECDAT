"""
ECDAT — Python Detector
==========================
Detects cryptographic artifacts in .py source files using Python's built-in
`ast` module — NOT regex. This is the same logic that used to live directly
inside scanner.py (CryptoASTVisitor + CALL_SIGNATURES + IMPORT_SIGNATURES);
it has been extracted, unchanged in behavior, so that Python has its own
detector file matching the shape of java_detector.py and c_detector.py.

WHY AST INSTEAD OF REGEX (for the viva)
------------------------------------------
Regex matches text patterns. AST (Abstract Syntax Tree) matches *meaning*.
`ast.parse()` turns source code into a tree of nodes that represent what the
code actually does — a function call, an import, an assignment — regardless
of how it's formatted, spaced, or commented. This means:
  - `RSA . generate ( 1024 )` (weird spacing) is still recognized as a call.
  - `# RSA.generate(2048)` (a comment) is NEVER recognized as a call, because
    comments don't exist in the parsed tree at all — they're stripped before
    parsing even begins. Regex would have to be taught to ignore comments;
    AST simply never sees them.
  - `print("RSA.generate(2048)")` (a string) is also never mistaken for a
    real call, for the same reason — it's a string literal node, not a call
    node.
This is what makes AST-based detection much stronger evidence than regex/
pattern matching, and is why AST detections get CONFIDENCE_AST_CALL (0.95)
while the C detector's regex-based detections are capped lower.

OUTPUT CONTRACT
------------------
Returns a list of plain dicts (via Artifact.to_dict()) matching the shared
CBOM-compatible schema defined in models.py. Calling convention matches
java_detector.scan_java_file(path) and c_detector.scan_c_file(path), so
scanner.py can route to all three language detectors identically.
"""

import ast
from typing import Optional

from scanner.models import (
    Artifact,
    CONFIDENCE_AST_CALL,
    CONFIDENCE_IMPORT_SIGNAL,
)


# Maps a function/class name (as it appears in a call, e.g. RSA.generate)
# to (algorithm, artifact_type, library_hint)
CALL_SIGNATURES = {
    "RSA.generate":             ("RSA", "algorithm", "Crypto.PublicKey"),
    "rsa.generate_private_key": ("RSA", "algorithm", "cryptography"),
    "ec.generate_private_key":  ("ECC", "algorithm", "cryptography"),
    "DSA.generate":              ("DSA", "algorithm", "Crypto.PublicKey"),
    "AES.new":                   ("AES", "algorithm", "Crypto.Cipher"),
    "DES.new":                   ("DES", "algorithm", "Crypto.Cipher"),
    "DES3.new":                  ("3DES", "algorithm", "Crypto.Cipher"),
    "ChaCha20.new":              ("ChaCha20", "algorithm", "Crypto.Cipher"),
    "hashlib.md5":                ("MD5", "hash", "hashlib"),
    "hashlib.sha1":               ("SHA-1", "hash", "hashlib"),
    "hashlib.sha256":             ("SHA-256", "hash", "hashlib"),
    "hashlib.sha384":             ("SHA-384", "hash", "hashlib"),
    "hashlib.sha512":             ("SHA-512", "hash", "hashlib"),
    "hashes.SHA256":              ("SHA-256", "hash", "cryptography"),
    "hashes.SHA1":                ("SHA-1", "hash", "cryptography"),
    "ec.SECP256R1":               ("ECC-P256", "algorithm", "cryptography"),
}

# Import statements that signal "this file uses crypto" even before we see
# a specific call - useful as a lower-confidence supporting signal. Per
# section 8 of the spec: `import hashlib` alone does NOT mean SHA-256 is
# used, so these are always tagged with CONFIDENCE_IMPORT_SIGNAL, never
# treated as confirmed usage.
IMPORT_SIGNATURES = {
    "Crypto.PublicKey": "Crypto.PublicKey",
    "Crypto.Cipher": "Crypto.Cipher",
    "Crypto.Hash": "Crypto.Hash",
    "cryptography.hazmat.primitives.asymmetric": "cryptography",
    "cryptography.hazmat.primitives.ciphers": "cryptography",
    "cryptography.hazmat.primitives.hashes": "cryptography",
    "hashlib": "hashlib",
}


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
        """
        Look for an integer literal argument or key_size=/bits= kwarg.
        NEVER guesses — if no explicit int literal is present, key_size
        stays None. This is a hard rule from the spec (section 9).
        """
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
                        artifact_type="import_signal",
                        algorithm="UNSPECIFIED",
                        key_size=None,
                        library=lib,
                        file_path=self.file_path,
                        line_number=node.lineno,
                        code_snippet=self._snippet(node.lineno),
                        detection_method="ast_import",
                        confidence=CONFIDENCE_IMPORT_SIGNAL,
                    ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for sig, lib in IMPORT_SIGNATURES.items():
            if module.startswith(sig):
                self.artifacts.append(Artifact(
                    artifact_type="import_signal",
                    algorithm="UNSPECIFIED",
                    key_size=None,
                    library=lib,
                    file_path=self.file_path,
                    line_number=node.lineno,
                    code_snippet=self._snippet(node.lineno),
                    detection_method="ast_import",
                    confidence=CONFIDENCE_IMPORT_SIGNAL,
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._call_name(node)
        if call_name in CALL_SIGNATURES:
            algorithm, artifact_type, library = CALL_SIGNATURES[call_name]
            key_size = self._extract_key_size(node)
            self.artifacts.append(Artifact(
                artifact_type=artifact_type,
                algorithm=algorithm,
                key_size=key_size,
                library=library,
                file_path=self.file_path,
                line_number=node.lineno,
                code_snippet=self._snippet(node.lineno),
                detection_method="ast_call",
                confidence=CONFIDENCE_AST_CALL,
            ))
        self.generic_visit(node)


def scan_python_file(file_path: str) -> list[dict]:
    """
    Entry point called by scanner.py for every .py file discovered.
    Returns a list of plain dicts (already CBOM-schema-compatible).
    Fails safe: a file with invalid Python syntax is skipped, not crashed on
    (section 21 of the spec — one bad file must never kill the whole scan).
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []
    visitor = CryptoASTVisitor(file_path, source.splitlines())
    visitor.visit(tree)
    return [a.to_dict() for a in visitor.artifacts]
