"""
ECDAT — Part 2: Recommendation Database
===========================================
Maintains the algorithm -> PQC/hybrid-alternative mapping table. This is
consumed both by Snigdha's CBOM output (as a suggestion field) and by
Samridhi's Part 3 recommendation logic (which adds risk-based prioritization
on top of this raw mapping).
"""

# algorithm -> (recommended_alternative, rationale, is_quantum_safe_already)
RECOMMENDATION_MAP = {
    "RSA":       ("ML-KEM (Kyber) for key exchange, ML-DSA (Dilithium) for signatures",
                   "RSA is broken by Shor's algorithm on a cryptographically-relevant quantum computer.",
                   False),
    "ECC":       ("ML-DSA (Dilithium) or FN-DSA (Falcon)",
                   "ECC/ECDSA relies on the elliptic-curve discrete log problem, broken by Shor's algorithm.",
                   False),
    "ECDSA":     ("ML-DSA (Dilithium) or FN-DSA (Falcon)",
                   "Same vulnerability as ECC — discrete log problem broken by Shor's algorithm.",
                   False),
    "DSA":       ("ML-DSA (Dilithium)",
                   "DSA relies on the discrete log problem, broken by Shor's algorithm.",
                   False),
    "DH":        ("ML-KEM (Kyber)",
                   "Diffie-Hellman key exchange is broken by Shor's algorithm.",
                   False),
    "MD5":       ("SHA-256 or SHA-3",
                   "MD5 is already broken classically (practical collision attacks exist) — not just a quantum concern.",
                   False),
    "SHA-1":     ("SHA-256 or SHA-3",
                   "SHA-1 is already broken classically (practical collision attacks demonstrated).",
                   False),
    "DES":       ("AES-256",
                   "DES's 56-bit key is far too small even without quantum computers.",
                   False),
    "3DES":      ("AES-256",
                   "3DES is deprecated; its effective 112-bit security is weak and it's being phased out industry-wide.",
                   False),
    "AES":       ("AES-256 (if not already)",
                   "AES is only weakened (not broken) by Grover's algorithm; AES-256 remains considered safe.",
                   True),
    "SHA-256":   ("No change needed (SHA-384+ optional for extra long-term margin)",
                   "SHA-256 is weakened but not broken by Grover's algorithm; generally still acceptable.",
                   True),
    "ChaCha20":  ("No change needed",
                   "Modern symmetric stream cipher with a 256-bit key; same Grover's-only weakening as AES-256.",
                   True),
}


def get_recommendation(algorithm: str) -> dict:
    if algorithm in RECOMMENDATION_MAP:
        alt, rationale, already_safe = RECOMMENDATION_MAP[algorithm]
        return {
            "recommended_alternative": alt,
            "rationale": rationale,
            "already_quantum_safe": already_safe,
        }
    return {
        "recommended_alternative": "Unknown — not in recommendation database",
        "rationale": "This algorithm was detected but has no mapped alternative yet. Flag for manual review.",
        "already_quantum_safe": False,
    }


def get_category_level_recommendation(cbom_category: str) -> dict:
    """
    Fallback recommendation for artifacts where the specific algorithm is
    UNSPECIFIED (typical for Certificate and Protocol category entries,
    which are often detected as 'a cert file exists' or 'TLS is used'
    without a resolved algorithm name attached).

    Without this, Certificate/Protocol entries would previously get NO
    recommendation at all — a real gap since two of the five required CBOM
    categories were silently excluded from the Recommendation Database
    deliverable.
    """
    category_guidance = {
        "Certificate": (
            "Inspect certificate's signature algorithm and key size directly; reissue with a "
            "quantum-safe algorithm (ML-DSA/Dilithium) if signed with RSA/ECDSA",
            "Certificates signed with RSA or ECDSA are only as quantum-safe as their underlying "
            "signature algorithm — the certificate itself must be re-issued during PQC migration.",
            False,
        ),
        "Protocol": (
            "Upgrade to TLS 1.3 with a PQC or hybrid (e.g. X25519+Kyber) key exchange",
            "Older TLS/SSL versions may negotiate quantum-vulnerable key exchange by default; "
            "protocol-level configuration must be updated independently of any single algorithm swap.",
            False,
        ),
    }
    if cbom_category in category_guidance:
        alt, rationale, already_safe = category_guidance[cbom_category]
        return {
            "recommended_alternative": alt,
            "rationale": rationale,
            "already_quantum_safe": already_safe,
        }
    return None


def attach_recommendations(merged_entries: list[dict]) -> list[dict]:
    """Adds a 'recommendation' field to every CBOM entry, non-destructively."""
    result = []
    for entry in merged_entries:
        e2 = dict(entry)
        if entry["algorithm"] != "UNSPECIFIED":
            e2["recommendation"] = get_recommendation(entry["algorithm"])
        else:
            # Previously: always None here, silently dropping Certificate/
            # Protocol entries from the Recommendation Database deliverable.
            # Now: fall back to category-level guidance for those two cases.
            e2["recommendation"] = get_category_level_recommendation(entry.get("cbom_category"))
        result.append(e2)
    return result
