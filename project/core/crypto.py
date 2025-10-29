# core/crypto.py
# Minimal port of your existing crypto helpers (scrypt, RSA, Fernet, hybrid)
import os
import base64
import hmac
import time
from hashlib import scrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Scrypt params (kept same behavior as original)
DEBUG_SCRYPT = False
DEFAULT_SCRYPT = dict(n=2**14, r=8, p=1, dklen=32)
DEBUG_SCRYPT_PARAMS = dict(n=2**12, r=8, p=1, dklen=32)

def get_scrypt_params():
    return DEBUG_SCRYPT_PARAMS if DEBUG_SCRYPT else DEFAULT_SCRYPT

def make_password_hash(password: str) -> str:
    salt = os.urandom(16)
    params = get_scrypt_params()
    dk = scrypt(password.encode('utf-8'), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=params['dklen'])
    return base64.b64encode(salt + dk).decode()

def verify_password(password: str, b64saltdk: str) -> bool:
    try:
        raw = base64.b64decode(b64saltdk.encode())
        salt, dk = raw[:16], raw[16:]
        params = get_scrypt_params()
        newdk = scrypt(password.encode('utf-8'), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=len(dk))
        return hmac.compare_digest(newdk, dk)
    except Exception:
        return False

def encrypt_with_password(data: bytes, password: str) -> str:
    salt = os.urandom(16)
    params = get_scrypt_params()
    dk = scrypt(password.encode(), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=params['dklen'])
    f = Fernet(base64.urlsafe_b64encode(dk))
    token = f.encrypt(data)
    return base64.b64encode(salt + token).decode()

def decrypt_with_password(token_b64: str, password: str) -> bytes:
    raw = base64.b64decode(token_b64.encode())
    salt, token = raw[:16], raw[16:]
    params = get_scrypt_params()
    dk = scrypt(password.encode(), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=params['dklen'])
    f = Fernet(base64.urlsafe_b64encode(dk))
    return f.decrypt(token)

def generate_rsa_keypair() -> (bytes, bytes):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem

def rsa_encrypt_with_public(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pub_pem)
    return pub.encrypt(plaintext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

def rsa_decrypt_with_private(priv_pem: bytes, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    return priv.decrypt(ciphertext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

def hybrid_encrypt_for_public(pub_pem_b64: str, message: str) -> dict:
    pub_pem = base64.b64decode(pub_pem_b64.encode())
    fk = Fernet.generate_key()
    f = Fernet(fk)
    ciphertext = f.encrypt(message.encode()).decode()
    enc_fk = rsa_encrypt_with_public(pub_pem, fk)
    return {'enc_fkey': base64.b64encode(enc_fk).decode(), 'payload': ciphertext}

def hybrid_decrypt_with_private_enc(priv_pem_bytes: bytes, enc_struct: dict) -> str:
    enc_fk = base64.b64decode(enc_struct['enc_fkey'].encode())
    fk = rsa_decrypt_with_private(priv_pem_bytes, enc_fk)
    f = Fernet(fk)
    return f.decrypt(enc_struct['payload'].encode()).decode()
