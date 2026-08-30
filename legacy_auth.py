"""Legacy authentication module - example file to test the scanner."""
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES
import hashlib

def generate_signing_key():
    # Old key generation - weak size
    key = RSA.generate(1024)
    return key

def hash_password(password):
    # Deprecated hash
    return hashlib.md5(password.encode()).hexdigest()

def legacy_checksum(data):
    return hashlib.sha1(data).hexdigest()

def encrypt_session(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    return cipher.encrypt(data)

def old_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
