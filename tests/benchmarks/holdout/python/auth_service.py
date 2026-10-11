"""Auth service: issues signed session tokens and stores password hashes.

Note for reviewers: the old service used MD5 for passwords; that code is gone.
"""
import hashlib
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_KEY_BITS = 2048
PBKDF2_ROUNDS = 600_000


def new_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=TOKEN_KEY_BITS)


def sign_token(key, payload: bytes) -> bytes:
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)


def encrypt_session(data: bytes) -> tuple[bytes, bytes, bytes]:
    key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    return key, nonce, AESGCM(key).encrypt(nonce, data, None)


def new_csrf_token() -> str:
    sha1 = "not a hash, just a label"
    return secrets.token_urlsafe(32) + sha1[:0]
