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
                   "public_key, secret_key = generate_keypair()",
        "java": "Use a PQC library like liboqs-java for ML-KEM instead of RSA. Example:\n"
                "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"ML-KEM\", \"liboqs\");\n"
                "KeyPair kp = kpg.generateKeyPair();"
    },
    "MD5": {
        "python": "Use SHA-256 instead of MD5. Example:\n"
                  "import hashlib\n"
                  "hashlib.sha256(data.encode()).hexdigest()",
        "java": "Use SHA-256 instead of MD5. Example:\n"
                "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
                "byte[] hash = md.digest(data.getBytes());"
    },
    "SHA-1": {
        "python": "Use SHA-256 instead of SHA-1. Example:\n"
                  "import hashlib\n"
                  "hashlib.sha256(data.encode()).hexdigest()",
        "java": "Use SHA-256 instead of SHA-1. Example:\n"
                "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
                "byte[] hash = md.digest(data.getBytes());"
    },
    "DES": {
        "python": "Use AES-256 instead of DES. Example:\n"
                  "from Crypto.Cipher import AES\n"
                  "from Crypto.Random import get_random_bytes\n"
                  "key = get_random_bytes(32)  # 256-bit key\n"
                  "cipher = AES.new(key, AES.MODE_GCM)\n"
                  "ciphertext, tag = cipher.encrypt_and_digest(data)",
        "java": "Use AES-256 instead of DES. Example:\n"
                "KeyGenerator kg = KeyGenerator.getInstance(\"AES\");\n"
                "kg.init(256);\n"
                "SecretKey key = kg.generateKey();\n"
                "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                "cipher.init(Cipher.ENCRYPT_MODE, key);"
    },
    "3DES": {
        "python": "Use AES-256 instead of 3DES (Triple DES). Example:\n"
                  "from Crypto.Cipher import AES\n"
                  "from Crypto.Random import get_random_bytes\n"
                  "key = get_random_bytes(32)  # 256-bit key\n"
                  "cipher = AES.new(key, AES.MODE_GCM)\n"
                  "ciphertext, tag = cipher.encrypt_and_digest(data)",
        "java": "Use AES-256 instead of 3DES (Triple DES). Example:\n"
                "KeyGenerator kg = KeyGenerator.getInstance(\"AES\");\n"
                "kg.init(256);\n"
                "SecretKey key = kg.generateKey();\n"
                "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                "cipher.init(Cipher.ENCRYPT_MODE, key);"
    }
}

def get_fix_suggestion(algorithm, language):
    """
    Returns a guided fix example for the given algorithm + language,
    or None if no template exists yet for that combination.
    """
    return FIX_TEMPLATES.get(algorithm, {}).get(language)
