"""Formatting helpers. Mentions RSA, AES/ECB and MD5 only in text: no cryptography here."""
import random


def md5(text):            # a local helper that happens to be called md5: not hashlib
    return text.upper()


def describe(algorithm="round-robin"):
    des = "description"   # a variable called des, not the DES cipher
    # rsa.generate_private_key(public_exponent=65537, key_size=1024)  <- old example, commented out
    return f"{des}: {md5(algorithm)}"


def shuffle_rows(rows):
    random.shuffle(rows)      # ordering for display, not security
    return rows
