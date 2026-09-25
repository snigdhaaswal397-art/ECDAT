"""
ECDAT — Part 1 extension: Java Detector
=========================================
Uses javalang (a real Java AST parser) to detect crypto artifacts in .java
files. Same output contract as scanner.py's Python detector.
"""


import uuid

import javalang
import javalang.tree
from typing import cast

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


def _artifact(algorithm, artifact_type, library, key_size, file_path, line, snippet, method, confidence, mode=None):
    res = {
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
    if mode:
        res["mode"] = mode
    return res


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

    for path, raw_node in tree.filter(javalang.tree.MethodInvocation):
        node = cast(javalang.tree.MethodInvocation, raw_node)
        member = getattr(node, "member", None)
        qualifier = getattr(node, "qualifier", None)
        arguments = getattr(node, "arguments", [])


        if member == "getInstance" and qualifier in JAVA_FACTORY_CLASSES:
            arguments = getattr(node, "arguments", [])

            if arguments:
                arg = arguments[0]
                alg_string = None
                if isinstance(arg, javalang.tree.Literal):
                    literal_value = getattr(arg, "value", None)

                    if literal_value is not None:
                        alg_string = str(literal_value).strip('"')

                if alg_string:
                    base_alg = alg_string.split('/')[0] if '/' in alg_string else alg_string
                    extracted_mode = None
                    if '/' in alg_string:
                        parts = alg_string.split('/')
                        if len(parts) > 1 and parts[1].upper() in ("GCM", "CBC", "ECB", "CTR", "CFB", "OFB"):
                            extracted_mode = parts[1].upper()

                    lookup_key = alg_string if alg_string in JAVA_ALGORITHM_MAP else base_alg
                    if lookup_key in JAVA_ALGORITHM_MAP:
                        algorithm, artifact_type = JAVA_ALGORITHM_MAP[lookup_key]
                        line = node.position.line if node.position else 0
                        snippet = source_lines[line - 1].strip() if 0 < line <= len(source_lines) else ""
                        artifacts.append(_artifact(
                            algorithm=algorithm,
                            artifact_type=artifact_type,
                            library=LIBRARY_MAP.get(qualifier, "java.security"),
                            key_size=None,  # resolved below if an initialize(N) call is nearby
                            file_path=file_path,
                            line=line,
                            snippet=snippet,
                            method="ast_call",
                            confidence=0.95,
                            mode=extracted_mode,
                        ))

        # Look for keyGen.initialize(1024) style calls to recover key size
        if member == "initialize" and arguments:
            arg = arguments[0]

            if isinstance(arg, javalang.tree.Literal):
                literal_value = getattr(arg, "value", None)
                position = getattr(node, "position", None)

                try:
                    if literal_value is not None:
                        size = int(literal_value)
                        line = position.line if position else 0
                        pending_key_size[line] = size
                except (ValueError, TypeError):
                    pass

    # Attach key sizes to the nearest preceding getInstance detection in the same method
    for a in artifacts:
        for line, size in pending_key_size.items():
            if 0 <= line - a["line_number"] <= 3:  # heuristic: initialize() a few lines after getInstance()
                a["key_size"] = size

    # Also catch import statements as lower-confidence supporting signals
    for path, node in tree.filter(javalang.tree.Import):
        path_value = getattr(node, "path", "")
        if path_value.startswith("javax.crypto") or path_value.startswith("java.security"):
            artifacts.append(_artifact(
            algorithm="UNSPECIFIED",
            artifact_type="import_signal",
            library=path_value,
            key_size=None,
            file_path=file_path,
            line=0,
            snippet=f"import {path_value};",
            method="ast_import",
            confidence=0.3,
        ))

    return artifacts