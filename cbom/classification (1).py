"""
ECDAT — Part 2: Artefact Classification
==========================================
Classifies each raw scanner-output artifact (from Part 1) into one of the
5 CBOM categories: Algorithm, Library, Certificate, Key, Protocol.

Part 1's `artifact_type` field (algorithm/hash/import_signal/certificate/
protocol) is a detection-level label. This module maps that — plus the
algorithm name and file path — into the business-level CBOM category the
handbook asks for.

UPDATE: Certificate and Protocol handling added so this module is ready
the moment the scanner (Vaishnavi's module) starts emitting those artifact
types — previously both silently fell through to "Uncategorized".
"""

# Algorithm-name -> category overrides for algorithm names that imply a
# specific category regardless of how the scanner tagged artifact_type.
ALGORITHM_CATEGORY_OVERRIDES = {
    "TLS-1.0": "Protocol",
    "TLS-1.1": "Protocol",
    "TLS-1.2": "Protocol",
    "TLS-1.3": "Protocol",
    "SSLv2": "Protocol",
    "SSLv3": "Protocol",
    "SSHv1": "Protocol",
    "SSHv2": "Protocol",
    "IPsec": "Protocol",
}

# Certain artifact_types from the scanner map directly to a CBOM category.
TYPE_CATEGORY_MAP = {
    "import_signal": "Library",
    "certificate": "Certificate",
    "protocol": "Protocol",
    "cert": "Certificate",
}

# File extensions that indicate a certificate (not a private/public key
# material file) — used as a fallback when artifact_type doesn't explicitly
# say "certificate" yet.
CERTIFICATE_FILE_EXTENSIONS = (".crt", ".pem", ".cer", ".p12", ".pfx", ".der")

# File extensions that indicate raw key material specifically — these route
# to "Key", not "Certificate", since a private/public key is a different
# CBOM category from a signed certificate even though both are security
# artifacts. (.pem CAN technically hold a key too, but is far more commonly
# a certificate in practice, so it stays in the certificate list above.)
KEY_FILE_EXTENSIONS = (".key",)

# Substrings in the algorithm/description field that indicate protocol
# usage even if not an exact match in ALGORITHM_CATEGORY_OVERRIDES —
# covers variants like "TLSv1.2" or "TLS 1.2" the scanner might emit.
PROTOCOL_KEYWORDS = ("TLS", "SSL", "SSH", "IPSEC", "IPsec")


def _looks_like_certificate_file(file_path: str) -> bool:
    if not file_path:
        return False
    return file_path.lower().endswith(CERTIFICATE_FILE_EXTENSIONS)


def _looks_like_key_file(file_path: str) -> bool:
    if not file_path:
        return False
    return file_path.lower().endswith(KEY_FILE_EXTENSIONS)


def _looks_like_protocol(algorithm: str) -> bool:
    if not algorithm or algorithm == "UNSPECIFIED":
        return False
    return any(keyword in algorithm.upper() for keyword in ("TLS", "SSL", "SSH", "IPSEC"))


def classify_artifact(artifact: dict) -> str:
    """
    Returns one of: "Algorithm", "Hash Function", "Library", "Certificate", "Key", "Protocol"
    """
    algorithm = artifact.get("algorithm", "UNSPECIFIED")
    artifact_type = artifact.get("artifact_type", "")
    file_path = artifact.get("file_path", "")

    # 1. Explicit algorithm-name override (most specific, checked first)
    if algorithm in ALGORITHM_CATEGORY_OVERRIDES:
        return ALGORITHM_CATEGORY_OVERRIDES[algorithm]

    # 2. Explicit artifact_type from the scanner
    if artifact_type in TYPE_CATEGORY_MAP:
        return TYPE_CATEGORY_MAP[artifact_type]

    # 3. Key file detection via extension (.key) — checked BEFORE certificate
    #    so standalone key material doesn't get miscategorized as a cert
    if _looks_like_key_file(file_path):
        return "Key"

    # 4. Certificate detection via file extension (fallback for scanners
    #    that report file discoveries without a specific type tag yet)
    if _looks_like_certificate_file(file_path):
        return "Certificate"

    # 5. Protocol detection via keyword match (fallback for TLS/SSL/SSH
    #    variants not caught by the exact-match override table above)
    if _looks_like_protocol(algorithm):
        return "Protocol"

    if artifact_type == "hash":
        return "Hash Function"

    if artifact_type == "algorithm":
        # key-generation calls with a key_size are meaningfully "Keys" for
        # inventory purposes, not just abstract algorithms
        if artifact.get("key_size") is not None and algorithm in ("RSA", "ECC", "DSA", "3DES"):
            return "Key"
        return "Algorithm"

    return "Uncategorized"


def classify_all(artifacts: list[dict]) -> list[dict]:
    """Adds a 'cbom_category' field to every artifact, non-destructively."""
    classified = []
    for a in artifacts:
        a2 = dict(a)
        a2["cbom_category"] = classify_artifact(a)
        classified.append(a2)
    return classified
