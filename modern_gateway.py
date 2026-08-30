"""Modern gateway module - example file to test the scanner."""
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES

def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())

def generate_strong_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def hash_data(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def encrypt_payload(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)
