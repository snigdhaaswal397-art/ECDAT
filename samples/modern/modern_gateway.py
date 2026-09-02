"""Modern gateway module - hybrid of good and lingering bad practices."""
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES

def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())

def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def compute_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    return digest


def encrypt_gcm(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)
