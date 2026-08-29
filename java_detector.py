"""
ECDAT — Part 1 extension: Java Detector
=========================================
Uses javalang (a real Java AST parser) to detect crypto artifacts in .java
files. Same output contract as scanner.py's Python detector.
"""

import uuid
from typing import Optional
import javalang

# Maps the string argument passed to getInstance(...) to (algorithm, artifact_type)
JAVA_ALGORITHM_MAP = {
    "MD5":              ("MD5", "hash"),
    "SHA-1":            ("SHA-1", "hash"),
    "SHA1":             ("SHA-1", "hash"),
    "SHA-256":          ("SHA-256", "hash"),
    "SHA256":           ("SHA-256", "hash"),
    "RSA":              ("RSA", "algorithm"),
    "DES":              ("DES", "algorithm"),
    "DESede":           ("3DES", "algorithm"),
    "AES":              ("AES", "algorithm"),
    "AES/GCM/NoPadding":("AES", "algorithm"),
    "AES/CBC/PKCS5Padding": ("AES", "algorithm"),
    "EC":               ("ECC", "algorithm"),
    "DSA":              ("DSA", "algorithm"),
    "SHA256withECDSA":  ("ECDSA", "algorithm"),
    "SHA256withRSA":    ("RSA", "algorithm"),
    "SHA1withDSA":      ("DSA", "algorithm"),
}

# Java crypto factory methods we watch for: ClassName.getInstance("...")
JAVA_FACTORY_CLASSES = {"MessageDigest", "Cipher", "KeyPairGenerator", "Signature", "KeyGenerator"}

LIBRARY_MAP = {
    "MessageDigest": "java.security",
    "Cipher": "javax.crypto",
    "KeyPairGenerator": "java.security",
    "Signature": "java.security",
    "KeyGenerator": "javax.crypto",
}


def _artifact(algorithm, artifact_type, library, key_size, file_path, line, snippet, method, confidence):
    return {
        "artifact_id": str(uuid.uuid4())[:8],
        "artifact_type": artifact_type,
        "algorithm": algorithm,
        "key_size": key_size,
        "library": library,
        "file_path": file_path,
        "line_number": line,
        "code_snippet": snippet,
        "detection_method": method,
        "confidence": confidence,
    }


def scan_java_file(file_path: str) -> list[dict]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()
    source_lines = source.splitlines()

    try:
        tree = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, Exception):
        return []

    artifacts = []
    pending_key_size = {}  # tracks generator.initialize(1024) calls by rough proximity

    for path, node in tree.filter(javalang.tree.MethodInvocation):
        if node.member == "getInstance" and node.qualifier in JAVA_FACTORY_CLASSES:
            if node.arguments:
                arg = node.arguments[0]
                alg_string = None
                if isinstance(arg, javalang.tree.Literal):
                    alg_string = arg.value.strip('"')

                if alg_string and alg_string in JAVA_ALGORITHM_MAP:
                    algorithm, artifact_type = JAVA_ALGORITHM_MAP[alg_string]
                    line = node.position.line if node.position else 0
                    snippet = source_lines[line - 1].strip() if 0 < line <= len(source_lines) else ""
                    artifacts.append(_artifact(
                        algorithm=algorithm,
                        artifact_type=artifact_type,
                        library=LIBRARY_MAP.get(node.qualifier, "java.security"),
                        key_size=None,  # resolved below if an initialize(N) call is nearby
                        file_path=file_path,
                        line=line,
                        snippet=snippet,
                        method="ast_call",
                        confidence=0.95,
                    ))

        # Look for keyGen.initialize(1024) style calls to recover key size
        if node.member == "initialize" and node.arguments:
            arg = node.arguments[0]
            if isinstance(arg, javalang.tree.Literal):
                try:
                    size = int(arg.value)
                    line = node.position.line if node.position else 0
                    pending_key_size[line] = size
                except ValueError:
                    pass

    # Attach key sizes to the nearest preceding getInstance detection in the same method
    for a in artifacts:
        for line, size in pending_key_size.items():
            if 0 <= line - a["line_number"] <= 3:  # heuristic: initialize() a few lines after getInstance()
                a["key_size"] = size

    # Also catch import statements as lower-confidence supporting signals
    for path, node in tree.filter(javalang.tree.Import):
        if node.path.startswith("javax.crypto") or node.path.startswith("java.security"):
            artifacts.append(_artifact(
                algorithm="UNSPECIFIED",
                artifact_type="import_signal",
                library=node.path,
                key_size=None,
                file_path=file_path,
                line=0,
                snippet=f"import {node.path};",
                method="ast_import",
                confidence=0.3,
            ))

    return artifacts
