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


def attach_recommendations(merged_entries: list[dict]) -> list[dict]:
    """Adds a 'recommendation' field to every CBOM entry, non-destructively."""
    result = []
    for entry in merged_entries:
        e2 = dict(entry)
        if entry["algorithm"] != "UNSPECIFIED":
            e2["recommendation"] = get_recommendation(entry["algorithm"])
        else:
            e2["recommendation"] = None
        result.append(e2)
    return result
