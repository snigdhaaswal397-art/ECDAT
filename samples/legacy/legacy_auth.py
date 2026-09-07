"""Legacy authentication module - deliberately insecure, scanner test fixture."""
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES
import hashlib

def generate_key():

    key = RSA.generate(1024)
    return key


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_data(data):
    return hashlib.sha1(data).hexdigest()

def encrypt_aes(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    return cipher.encrypt(data)

def encrypt_des(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
