import re
from pathlib import Path

from scanner.models import Artifact


# ---------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------

HIGH_CONFIDENCE = 0.70
LOW_CONFIDENCE = 0.30


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _make_artifact(
    algorithm,
    file_path,
    line_number,
    code_snippet,
    detection_method="pattern_match",
    confidence=HIGH_CONFIDENCE,
    artifact_type="algorithm",
    key_size=None,
    library="Unknown",
):
    return Artifact(
        artifact_id=f"{Path(file_path).name}:{line_number}:{algorithm}",
        artifact_type=artifact_type,
        algorithm=algorithm,
        key_size=key_size,
        library=library,
        file_path=str(file_path),
        line_number=line_number,
        code_snippet=code_snippet.strip(),
        detection_method=detection_method,
        confidence=confidence,
    )


def _line_number(source, position):
    return source.count("\n", 0, position) + 1


def _snippet_for_line(source, line_number):
    lines = source.splitlines()

    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()

    return ""


# ---------------------------------------------------------
# Algorithm detection
# ---------------------------------------------------------

ALGORITHM_PATTERNS = [
    (r"\bmd5\b", "MD5"),
    (r"\bsha[-_]?1\b", "SHA-1"),
    (r"\bsha[-_]?256\b", "SHA-256"),
    (r"\bsha[-_]?384\b", "SHA-384"),
    (r"\bsha[-_]?512\b", "SHA-512"),

    (r"\baes\b", "AES"),
    (r"\bdes\b", "DES"),
    (r"\b3des\b", "3DES"),
    (r"\btripledes\b", "3DES"),

    (r"\brsa\b", "RSA"),
    (r"\becdsa\b", "ECDSA"),
    (r"\becdh\b", "ECDH"),
    (r"\bec\b", "ECC"),
]


# ---------------------------------------------------------
# Node.js crypto API patterns
# ---------------------------------------------------------

NODE_CRYPTO_APIS = [
    r"\bcrypto\.createHash\s*\(",
    r"\bcrypto\.createHmac\s*\(",
    r"\bcrypto\.createCipheriv\s*\(",
    r"\bcrypto\.createDecipheriv\s*\(",
    r"\bcrypto\.createSign\s*\(",
    r"\bcrypto\.createVerify\s*\(",
    r"\bcrypto\.generateKeyPair\s*\(",
    r"\bcrypto\.generateKeyPairSync\s*\(",
    r"\bcrypto\.createPrivateKey\s*\(",
    r"\bcrypto\.createPublicKey\s*\(",
]


# ---------------------------------------------------------
# Web Crypto API patterns
# ---------------------------------------------------------

WEB_CRYPTO_APIS = [
    r"\bcrypto\.subtle\.digest\s*\(",
    r"\bcrypto\.subtle\.sign\s*\(",
    r"\bcrypto\.subtle\.verify\s*\(",
    r"\bcrypto\.subtle\.encrypt\s*\(",
    r"\bcrypto\.subtle\.decrypt\s*\(",
    r"\bcrypto\.subtle\.generateKey\s*\(",
]


# ---------------------------------------------------------
# Imports / requires
# ---------------------------------------------------------

CRYPTO_IMPORT_PATTERNS = [
    r'require\s*\(\s*["\']crypto["\']\s*\)',
    r'import\s+.*?\s+from\s+["\']crypto["\']',
    r'import\s+["\']crypto["\']',
]


# ---------------------------------------------------------
# Main detector
# ---------------------------------------------------------

def scan_javascript_file(file_path):
    """
    Scan JavaScript / TypeScript source code for
    cryptographic artefacts.

    Supports:
        .js
        .jsx
        .ts
        .tsx
    """

    artifacts = []

    try:
        source = Path(file_path).read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return artifacts

    # -----------------------------------------------------
    # Remove comments for detection.
    # This prevents comments from becoming crypto findings.
    # -----------------------------------------------------

    source_without_comments = re.sub(
        r"//.*?$|/\*.*?\*/",
        "",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )

    # -----------------------------------------------------
    # 1. Detect Node.js crypto API usage
    # -----------------------------------------------------

    for api_pattern in NODE_CRYPTO_APIS:

        for match in re.finditer(
            api_pattern,
            source_without_comments,
            re.IGNORECASE,
        ):
            position = match.start()

            line_number = _line_number(
                source,
                position,
            )

            snippet = _snippet_for_line(
                source,
                line_number,
            )

            # Look at the surrounding call for algorithm names.
            start = max(0, position - 100)
            end = min(
                len(source_without_comments),
                position + 250,
            )

            context = source_without_comments[start:end]

            found_algorithm = False

            for pattern, algorithm in ALGORITHM_PATTERNS:

                algorithm_match = re.search(
                    pattern,
                    context,
                    re.IGNORECASE,
                )

                if algorithm_match:
                    artifacts.append(
                        _make_artifact(
                            algorithm=algorithm,
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=snippet,
                            confidence=HIGH_CONFIDENCE,
                            library="Node.js crypto",
                        )
                    )

                    found_algorithm = True

            # API is clearly cryptographic but algorithm is unknown.
            if not found_algorithm:
                artifacts.append(
                    _make_artifact(
                        algorithm="UNSPECIFIED",
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=snippet,
                        confidence=HIGH_CONFIDENCE,
                        library="Node.js crypto",
                    )
                )

    # -----------------------------------------------------
    # 2. Detect Web Crypto API usage
    # -----------------------------------------------------

    for api_pattern in WEB_CRYPTO_APIS:

        for match in re.finditer(
            api_pattern,
            source_without_comments,
            re.IGNORECASE,
        ):
            position = match.start()

            line_number = _line_number(
                source,
                position,
            )

            snippet = _snippet_for_line(
                source,
                line_number,
            )

            start = max(0, position - 100)
            end = min(
                len(source_without_comments),
                position + 300,
            )

            context = source_without_comments[start:end]

            found_algorithm = False

            for pattern, algorithm in ALGORITHM_PATTERNS:

                if re.search(
                    pattern,
                    context,
                    re.IGNORECASE,
                ):
                    artifacts.append(
                        _make_artifact(
                            algorithm=algorithm,
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=snippet,
                            confidence=HIGH_CONFIDENCE,
                            library="Web Crypto API",
                        )
                    )

                    found_algorithm = True

            if not found_algorithm:
                artifacts.append(
                    _make_artifact(
                        algorithm="UNSPECIFIED",
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=snippet,
                        confidence=HIGH_CONFIDENCE,
                        library="Web Crypto API",
                    )
                )

    # -----------------------------------------------------
    # 3. Detect crypto imports
    # -----------------------------------------------------
    # Import alone is NOT actual algorithm usage.
    # Therefore confidence is low.
    # -----------------------------------------------------

    for pattern in CRYPTO_IMPORT_PATTERNS:

        for match in re.finditer(
            pattern,
            source_without_comments,
            re.IGNORECASE,
        ):
            position = match.start()

            line_number = _line_number(
                source,
                position,
            )

            snippet = _snippet_for_line(
                source,
                line_number,
            )

            artifacts.append(
                _make_artifact(
                    algorithm="UNSPECIFIED",
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=snippet,
                    confidence=LOW_CONFIDENCE,
                    library="Node.js crypto",
                    detection_method="import_signal",
                )
            )

    return artifacts