"""
ECDAT — Part 2: Fix-it Suggestions
====================================
Provides a guided before/after example for each detected weak algorithm.
This does NOT auto-rewrite the user's code — it shows a reference example
of how the fix would look, using the algorithm mapping already defined
in recommendation_db.py.
"""
FIX_TEMPLATES = {
    "RSA": {
        "python": "Use ML-KEM (Kyber) instead of RSA.generate(). Example:\n"
                   "from pqcrypto.kem.ml_kem_512 import generate_keypair\n"
                   "public_key, secret_key = generate_keypair()"
    },
    "MD5": {
        "python": "Use SHA-256 instead of MD5. Example:\n"
                  "import hashlib\n"
                  "hashlib.sha256(data.encode()).hexdigest()"
    }
}
def get_fix_suggestion(algorithm, language):
    """
    Returns a guided fix example for the given algorithm + language,
    or None if no template exists yet for that combination.
    """
    return FIX_TEMPLATES.get(algorithm, {}).get(language)