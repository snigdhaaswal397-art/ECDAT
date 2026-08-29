"""
ECDAT — Part 2: Artefact Classification
==========================================
Classifies each raw scanner-output artifact (from Part 1) into one of the
5 CBOM categories: Algorithm, Library, Certificate, Key, Protocol.

Part 1's `artifact_type` field (algorithm/hash/import_signal) is a
detection-level label. This module maps that — plus the algorithm name
itself — into the business-level CBOM category the handbook asks for.
"""

# Algorithm-name -> category overrides for cases where the raw type is
# ambiguous or where a specific algorithm implies a specific category.
ALGORITHM_CATEGORY_OVERRIDES = {
    # Protocols aren't emitted by Part 1 yet (no TLS-version detector built
    # so far) but this map is where that would slot in once it exists.
    "TLS-1.0": "Protocol",
    "TLS-1.1": "Protocol",
    "TLS-1.2": "Protocol",
    "SSHv1": "Protocol",
}

# Certain artifact_types from Part 1 map directly to a CBOM category.
TYPE_CATEGORY_MAP = {
    "import_signal": "Library",
}


def classify_artifact(artifact: dict) -> str:
    """
    Returns one of: "Algorithm", "Hash Function", "Library", "Certificate", "Key", "Protocol"
    """
    algorithm = artifact.get("algorithm", "UNSPECIFIED")
    artifact_type = artifact.get("artifact_type", "")

    if algorithm in ALGORITHM_CATEGORY_OVERRIDES:
        return ALGORITHM_CATEGORY_OVERRIDES[algorithm]

    if artifact_type in TYPE_CATEGORY_MAP:
        return TYPE_CATEGORY_MAP[artifact_type]

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
