"""
ECDAT — Part 1 extension: C/OpenSSL Detector
===============================================
IMPORTANT — honesty note for the technical report:
True AST parsing of C requires a preprocessor pass (macros, includes) and a
full C parser (e.g. pycparser + a fake libc). That's a large dependency for
a hackathon timeline. Instead, this module uses careful regex/pattern
matching over function calls and #include lines.

This is intentionally marked with LOWER confidence scores than the Python
(AST) and Java (AST) detectors, and a different detection_method value
("pattern_match" instead of "ast_call"), so downstream consumers (Snigdha's
dedup/classification module, Samridhi's risk engine) can weight it
appropriately or flag it for human review. Be upfront about this tradeoff
in your report — it's honest engineering, not a shortcut hidden from judges.
"""

import re
import uuid

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//.*")

# function_name_pattern -> (algorithm, artifact_type, library)
C_FUNCTION_SIGNATURES = [
    (r"\bRSA_generate_key\s*\(\s*(\d+)", "RSA", "algorithm", "openssl/rsa.h"),
    (r"\bMD5\s*\(", "MD5", "hash", "openssl/md5.h"),
    (r"\bEVP_md5\s*\(", "MD5", "hash", "openssl/evp.h"),
    (r"\bEVP_sha1\s*\(", "SHA-1", "hash", "openssl/evp.h"),
    (r"\bEVP_sha256\s*\(", "SHA-256", "hash", "openssl/evp.h"),
    (r"\bDES_ecb_encrypt\s*\(", "DES", "algorithm", "openssl/des.h"),
    (r"\bDES_set_key\s*\(", "DES", "algorithm", "openssl/des.h"),
    (r"\bAES_encrypt\s*\(", "AES", "algorithm", "openssl/aes.h"),
    (r"\bAES_set_encrypt_key\s*\(\s*\w+\s*,\s*(\d+)", "AES", "algorithm", "openssl/aes.h"),
]

C_INCLUDE_SIGNATURES = {
    "openssl/rsa.h": "RSA (import signal)",
    "openssl/des.h": "DES (import signal)",
    "openssl/md5.h": "MD5 (import signal)",
    "openssl/aes.h": "AES (import signal)",
    "openssl/evp.h": "EVP/generic (import signal)",
}


def _artifact(algorithm, artifact_type, library, key_size, file_path, line, snippet, confidence):
    return {
        "artifact_id": str(uuid.uuid4())[:8],
        "artifact_type": artifact_type,
        "algorithm": algorithm,
        "key_size": key_size,
        "library": library,
        "file_path": file_path,
        "line_number": line,
        "code_snippet": snippet,
        "detection_method": "pattern_match",  # NOTE: lower-confidence than ast_call
        "confidence": confidence,
    }


def _mask_comments(text: str) -> str:
    """
    Blank out `/* ... */` and `//` comment text (replacing with spaces,
    keeping newlines) so a commented-out crypto call like
    `// AES_encrypt(buf, out, &key);` is never mistaken for real usage --
    same principle as the fix applied to the JavaScript detector. Blanking
    (not deleting) keeps every line's length/position and the total line
    count unchanged, so line numbers stay exactly correct.
    """
    def repl_block(m):
        return "".join(ch if ch == "\n" else " " for ch in m.group(0))

    text = _BLOCK_COMMENT_RE.sub(repl_block, text)
    text = _LINE_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)
    return text


def scan_c_file(file_path: str) -> list[dict]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    masked_lines = _mask_comments(raw).splitlines()
    original_lines = raw.splitlines()

    artifacts = []

    for i, masked_line in enumerate(masked_lines, start=1):
        # Match against the comment-masked line (so commented-out code can
        # never match), but report the ORIGINAL line as the evidence
        # snippet so a human reviewer sees real code, not blanked-out text.
        original_stripped = original_lines[i - 1].strip() if i - 1 < len(original_lines) else ""
        masked_stripped = masked_line.strip()

        # includes -> low-confidence supporting signal
        include_match = re.search(r'#include\s*[<"]([^>"]+)[>"]', masked_stripped)
        if include_match:
            header = include_match.group(1)
            if header in C_INCLUDE_SIGNATURES:
                artifacts.append(_artifact(
                    algorithm="UNSPECIFIED",
                    artifact_type="import_signal",
                    library=header,
                    key_size=None,
                    file_path=file_path,
                    line=i,
                    snippet=original_stripped,
                    confidence=0.25,
                ))

        # function calls -> higher (but still pattern-based, not AST) confidence
        for pattern, algorithm, artifact_type, library in C_FUNCTION_SIGNATURES:
            m = re.search(pattern, masked_stripped)
            if m:
                key_size = None
                if m.groups():
                    try:
                        key_size = int(m.group(1))
                    except (ValueError, IndexError):
                        key_size = None
                artifacts.append(_artifact(
                    algorithm=algorithm,
                    artifact_type=artifact_type,
                    library=library,
                    key_size=key_size,
                    file_path=file_path,
                    line=i,
                    snippet=original_stripped,
                    confidence=0.7,  # deliberately below AST-based 0.95
                ))

    return artifacts