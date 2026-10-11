"""Payments gateway helpers: session keys, webhook tags, stored secrets, API tokens."""
import hashlib as h
import hmac
from random import SystemRandom

import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def session_key(peer_public):
    """Ephemeral ECDH on P-256, then HKDF-SHA256 -> 32-byte session key."""
    mine = ec.generate_private_key(ec.SECP256R1())
    shared = mine.exchange(ec.ECDH(), peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session").derive(shared)


def fingerprint(blob: bytes) -> str:
    return h.sha1(blob).hexdigest()


def webhook_tag(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, h.md5).hexdigest()


def secret_box() -> Fernet:
    return Fernet(Fernet.generate_key())


def api_token(claims: dict, private_pem: bytes) -> str:
    return jwt.encode(claims, private_pem, algorithm="RS256")


def shuffle_batch(items: list) -> None:
    SystemRandom().shuffle(items)
