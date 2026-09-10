
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
    mode=None,
):
    return Artifact(
        artifact_type=artifact_type,
        algorithm=algorithm,
        key_size=key_size,
        library=library,
        file_path=str(file_path),
        line_number=line_number,
        code_snippet=code_snippet.strip(),
        detection_method=detection_method,
        confidence=confidence,
        mode=mode,
    )


def _line_number(source, position):
    return source.count("\n", 0, position) + 1


def _snippet_for_line(source, line_number):
    lines = source.splitlines()

    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()

    return ""


def _mask_comments(source):
    """
    Replace JavaScript comments with spaces while preserving:
    - string length
    - newline positions
    - character offsets

    Handles:
        // single-line comments
        /* multi-line comments */
    """

    def replace_comment(match):
        text = match.group(0)

        return "".join(
            "\n" if char == "\n" else " "
            for char in text
        )

    comment_pattern = r"//[^\n]*|/\*[\s\S]*?\*/"

    return re.sub(
        comment_pattern,
        replace_comment,
        source,
    )


def _extract_call_arguments(text, open_paren_index):
    """
    Return only the contents of the API call's parentheses.

    Example:

        crypto.createHash("sha256")

    returns:

        "sha256"

    It also handles nested objects, arrays and function calls.
    """

    depth = 0
    i = open_paren_index
    start = open_paren_index + 1
    n = len(text)

    in_string = None

    while i < n:
        char = text[i]

        if in_string:
            if char == "\\":
                i += 2
                continue

            if char == in_string:
                in_string = None

        else:
            if char in ("'", '"', "`"):
                in_string = char

            elif char in "([{":
                depth += 1

            elif char in ")]}":
                depth -= 1

                if depth == 0 and char == ")":
                    return text[start:i]

        i += 1

    # Malformed/truncated source.
    return text[start:]


def _first_argument(args_text):
    """
    Extract the first argument from a function call.

    Example:

        "sha256", something

    returns:

        "sha256"

    This is intentionally simple and is used only for APIs where
    the first argument has a defined cryptographic meaning.
    """

    depth = 0
    in_string = None

    for i, char in enumerate(args_text):

        if in_string:
            if char == "\\":
                continue

            if char == in_string:
                in_string = None

            continue

        if char in ("'", '"', "`"):
            in_string = char
            continue

        if char in "([{":
            depth += 1
            continue

        if char in ")]}":
            depth -= 1
            continue

        if char == "," and depth == 0:
            return args_text[:i].strip()

    return args_text.strip()


def _find_algorithm(patterns, text):
    """
    Return the first matching algorithm.

    Unlike the previous implementation, this function does NOT
    search every crypto algorithm against every API indiscriminately.
    The caller provides the patterns appropriate for that API.
    """

    for pattern, algorithm in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return algorithm

    return None


def _extract_rsa_key_size(args_text):
    """
    Extract:

        modulusLength: 2048

    from a generateKeyPair() options object.
    """

    match = re.search(
        r"\bmodulusLength\s*:\s*(\d+)",
        args_text,
        re.IGNORECASE,
    )

    if match:
        return int(match.group(1))

    return None


# ---------------------------------------------------------
# Algorithm patterns
# ---------------------------------------------------------

HASH_ALGORITHMS = [
    (r"\bmd5\b", "MD5"),
    (r"\bsha[-_]?1\b", "SHA-1"),
    (r"\bsha[-_]?224\b", "SHA-224"),
    (r"\bsha[-_]?256\b", "SHA-256"),
    (r"\bsha[-_]?384\b", "SHA-384"),
    (r"\bsha[-_]?512\b", "SHA-512"),
]

CIPHER_ALGORITHMS = [
    (r"\baes[-_]?(?:128|192|256)?[-_]?(?:cbc|gcm|ctr|ecb|ccm)\b", "AES"),
    (r"\baes\b", "AES"),
    (r"\bdes\b", "DES"),
    (r"\b3des\b", "3DES"),
    (r"\btripledes\b", "3DES"),
    (r"\bchacha20\b", "ChaCha20"),
    (r"\bchacha20-poly1305\b", "ChaCha20-Poly1305"),
]

KEY_GENERATION_ALGORITHMS = [
    (r"\brsa\b", "RSA"),
    (r"\bec\b", "ECC"),
    (r"\becdsa\b", "ECDSA"),
    (r"\becdh\b", "ECDH"),
    (r"\bdsa\b", "DSA"),
]

SIGNATURE_ALGORITHMS = [
    (r"\brsa\b", "RSA"),
    (r"\brsa[-_]pss\b", "RSA-PSS"),
    (r"\becdsa\b", "ECDSA"),
    (r"\bdsa\b", "DSA"),
]

WEB_CRYPTO_ALGORITHMS = [
    (r"\bsha[-_]?1\b", "SHA-1"),
    (r"\bsha[-_]?256\b", "SHA-256"),
    (r"\bsha[-_]?384\b", "SHA-384"),
    (r"\bsha[-_]?512\b", "SHA-512"),
    (r"\baes[-_]gcm\b", "AES"),
    (r"\baes[-_]cbc\b", "AES"),
    (r"\baes[-_]ctr\b", "AES"),
    (r"\brsa[-_]oaep\b", "RSA"),
    (r"\brsa[-_]pss\b", "RSA-PSS"),
    (r"\becdsa\b", "ECDSA"),
    (r"\becdh\b", "ECDH"),
    (r"\bhmac\b", "HMAC"),
]


# ---------------------------------------------------------
# Node.js crypto API patterns
# ---------------------------------------------------------

NODE_CRYPTO_APIS = {
    "createHash": r"\bcrypto\.createHash\s*\(",
    "createHmac": r"\bcrypto\.createHmac\s*\(",
    "createCipheriv": r"\bcrypto\.createCipheriv\s*\(",
    "createDecipheriv": r"\bcrypto\.createDecipheriv\s*\(",
    "createSign": r"\bcrypto\.createSign\s*\(",
    "createVerify": r"\bcrypto\.createVerify\s*\(",
    "generateKeyPair": r"\bcrypto\.generateKeyPair\s*\(",
    "generateKeyPairSync": r"\bcrypto\.generateKeyPairSync\s*\(",
    "createPrivateKey": r"\bcrypto\.createPrivateKey\s*\(",
    "createPublicKey": r"\bcrypto\.createPublicKey\s*\(",
}


# ---------------------------------------------------------
# Web Crypto API patterns
# ---------------------------------------------------------

WEB_CRYPTO_APIS = {
    "digest": r"\bcrypto\.subtle\.digest\s*\(",
    "sign": r"\bcrypto\.subtle\.sign\s*\(",
    "verify": r"\bcrypto\.subtle\.verify\s*\(",
    "encrypt": r"\bcrypto\.subtle\.encrypt\s*\(",
    "decrypt": r"\bcrypto\.subtle\.decrypt\s*\(",
    "generateKey": r"\bcrypto\.subtle\.generateKey\s*\(",
}


# ---------------------------------------------------------
# Imports / requires
# ---------------------------------------------------------

CRYPTO_IMPORT_PATTERNS = [
    r'\brequire\s*\(\s*["\']crypto["\']\s*\)',
    r'\bimport\s+.*?\s+from\s+["\']crypto["\']',
    r'\bimport\s+["\']crypto["\']',
]


# ---------------------------------------------------------
# Node.js API detector
# ---------------------------------------------------------

def _scan_node_crypto_api(
    api_name,
    match,
    source,
    masked,
    file_path,
):
    """
    Detect the cryptographic algorithm associated with one
    specific Node.js crypto API.
    """

    position = match.start()

    line_number = _line_number(
        source,
        position,
    )

    snippet = _snippet_for_line(
        source,
        line_number,
    )

    open_paren_index = match.end() - 1

    args_text = _extract_call_arguments(
        masked,
        open_paren_index,
    )

    first_argument = _first_argument(
        args_text
    )

    algorithm = None
    key_size = None

    mode = None

    # -----------------------------------------------------
    # Hash APIs
    # -----------------------------------------------------

    if api_name in {
        "createHash",
        "createHmac",
    }:
        algorithm = _find_algorithm(
            HASH_ALGORITHMS,
            first_argument,
        )

        artifact_type = "hash"

    # -----------------------------------------------------
    # Cipher APIs
    # -----------------------------------------------------

    elif api_name in {
        "createCipheriv",
        "createDecipheriv",
    }:
        algorithm = _find_algorithm(
            CIPHER_ALGORITHMS,
            first_argument,
        )

        artifact_type = "algorithm"
        mode_match = re.search(r"\b(gcm|cbc|ctr|ecb|ccm|cfb|ofb)\b", first_argument, re.IGNORECASE)
        if mode_match:
            mode = mode_match.group(1).upper()

    # -----------------------------------------------------
    # Key-pair generation
    # -----------------------------------------------------

    elif api_name in {
        "generateKeyPair",
        "generateKeyPairSync",
    }:
        algorithm = _find_algorithm(
            KEY_GENERATION_ALGORITHMS,
            first_argument,
        )

        artifact_type = "algorithm"

        if algorithm == "RSA":
            key_size = _extract_rsa_key_size(
                args_text
            )

    # -----------------------------------------------------
    # Signing / verification
    # -----------------------------------------------------

    elif api_name in {
        "createSign",
        "createVerify",
    }:
        algorithm = _find_algorithm(
            SIGNATURE_ALGORITHMS,
            first_argument,
        )

        artifact_type = "algorithm"

    # -----------------------------------------------------
    # Key import/export APIs
    # -----------------------------------------------------

    elif api_name in {
        "createPrivateKey",
        "createPublicKey",
    }:
        # These APIs often receive a PEM/DER key object rather
        # than an explicit algorithm. Do not guess RSA/ECC.
        algorithm = None
        artifact_type = "key"

    else:
        artifact_type = "algorithm"

    # -----------------------------------------------------
    # Create finding
    # -----------------------------------------------------

    if algorithm:
        return _make_artifact(
            algorithm=algorithm,
            file_path=file_path,
            line_number=line_number,
            code_snippet=snippet,
            confidence=HIGH_CONFIDENCE,
            library="Node.js crypto",
            artifact_type=artifact_type,
            key_size=key_size,
            mode=mode,
        )

    # The API itself is cryptographic, but the algorithm could
    # not be determined statically.
    return _make_artifact(
        algorithm="UNSPECIFIED",
        file_path=file_path,
        line_number=line_number,
        code_snippet=snippet,
        confidence=HIGH_CONFIDENCE,
        library="Node.js crypto",
        artifact_type=artifact_type,
        key_size=key_size,
        mode=mode,
    )


# ---------------------------------------------------------
# Web Crypto API detector
# ---------------------------------------------------------

def _scan_web_crypto_api(
    api_name,
    match,
    source,
    masked,
    file_path,
):
    """
    Detect algorithms used through the Web Crypto API.
    """

    position = match.start()

    line_number = _line_number(
        source,
        position,
    )

    snippet = _snippet_for_line(
        source,
        line_number,
    )

    open_paren_index = match.end() - 1

    args_text = _extract_call_arguments(
        masked,
        open_paren_index,
    )

    algorithm = _find_algorithm(
        WEB_CRYPTO_ALGORITHMS,
        args_text,
    )

    # digest() has the algorithm as its first argument.
    if api_name == "digest":
        algorithm = _find_algorithm(
            WEB_CRYPTO_ALGORITHMS,
            _first_argument(args_text),
        )

    artifact_type = "algorithm"

    if api_name == "digest":
        artifact_type = "hash"

    if algorithm:
        return _make_artifact(
            algorithm=algorithm,
            file_path=file_path,
            line_number=line_number,
            code_snippet=snippet,
            confidence=HIGH_CONFIDENCE,
            library="Web Crypto API",
            artifact_type=artifact_type,
        )

    return _make_artifact(
        algorithm="UNSPECIFIED",
        file_path=file_path,
        line_number=line_number,
        code_snippet=snippet,
        confidence=HIGH_CONFIDENCE,
        library="Web Crypto API",
        artifact_type=artifact_type,
    )


# ---------------------------------------------------------
# Main detector
# ---------------------------------------------------------

def scan_javascript_file(file_path):
    """
    Scan JavaScript / TypeScript source code for
    cryptographic API usage.

    Supports:

        .js
        .jsx
        .ts
        .tsx

    Detection methods:

        1. Node.js crypto API regex
        2. Web Crypto API regex
        3. crypto import/require signal
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
    # Mask comments
    # -----------------------------------------------------

    masked = _mask_comments(source)

    # -----------------------------------------------------
    # 1. Node.js crypto APIs
    # -----------------------------------------------------

    for api_name, api_pattern in NODE_CRYPTO_APIS.items():

        for match in re.finditer(
            api_pattern,
            masked,
            re.IGNORECASE,
        ):

            artifact = _scan_node_crypto_api(
                api_name=api_name,
                match=match,
                source=source,
                masked=masked,
                file_path=file_path,
            )

            artifacts.append(artifact)

    # -----------------------------------------------------
    # 2. Web Crypto APIs
    # -----------------------------------------------------

    for api_name, api_pattern in WEB_CRYPTO_APIS.items():

        for match in re.finditer(
            api_pattern,
            masked,
            re.IGNORECASE,
        ):

            artifact = _scan_web_crypto_api(
                api_name=api_name,
                match=match,
                source=source,
                masked=masked,
                file_path=file_path,
            )

            artifacts.append(artifact)

    # -----------------------------------------------------
    # 3. Imports / require
    # -----------------------------------------------------

    for pattern in CRYPTO_IMPORT_PATTERNS:

        for match in re.finditer(
            pattern,
            masked,
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
                    artifact_type="import_signal",
                )
            )

    return artifacts

