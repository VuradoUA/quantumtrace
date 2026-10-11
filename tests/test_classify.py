"""Unit tests for the classifier: the Shor / Grover / HNDL rules, plus the
traps that cost detection-accuracy points."""
import pytest

from quantumtrace.classify import classify, classify_name
from quantumtrace.models import Finding, Tier, Usage


def tier(name, **kw):
    return classify_name(name, **kw).tier


# ---------------------------------------------------------------- the three official tiers
@pytest.mark.parametrize("name,kw,expected", [
    # Shor -> CRITICAL, whatever the key size
    ("RSA", {"key_size": 2048}, Tier.CRITICAL),
    ("RSA_4096", {}, Tier.CRITICAL),                 # bigger key does NOT help
    ("RSA", {"key_size": 15360}, Tier.CRITICAL),
    ("ECDSA", {}, Tier.CRITICAL),
    ("secp256r1", {}, Tier.CRITICAL),
    ("X25519", {}, Tier.CRITICAL),
    ("Ed25519", {}, Tier.CRITICAL),
    ("DH", {"key_size": 4096}, Tier.CRITICAL),
    ("DSA", {}, Tier.CRITICAL),
    # Grover -> MEDIUM below 256-bit strength
    ("AES", {"key_size": 128}, Tier.MEDIUM),
    ("AES-192", {}, Tier.MEDIUM),
    ("3DES", {}, Tier.MEDIUM),
    ("DESede", {}, Tier.MEDIUM),
    ("SHA-1", {}, Tier.MEDIUM),
    ("MD5", {}, Tier.MEDIUM),
    ("HmacSHA1", {}, Tier.MEDIUM),
    # SAFE
    ("AES", {"key_size": 256}, Tier.SAFE),
    ("aes256-gcm@openssh.com", {}, Tier.SAFE),
    ("ChaCha20-Poly1305", {}, Tier.SAFE),
    ("SHA-256", {}, Tier.SAFE),
    ("SHA3-512", {}, Tier.SAFE),
    ("HMAC-SHA256", {}, Tier.SAFE),
    ("ML-KEM-768", {}, Tier.SAFE),
    ("ML_DSA_65", {}, Tier.SAFE),
    ("SLH-DSA-SHA2-128s", {}, Tier.SAFE),
    ("X25519MLKEM768", {}, Tier.SAFE),
])
def test_tiers(name, kw, expected):
    assert tier(name, **kw) is expected


# ---------------------------------------------------------------- extra tiers
def test_aes_without_key_size_is_unknown_not_guessed():
    c = classify_name("AES")
    assert c.tier is Tier.UNKNOWN and "key-size-unknown" in c.flags


def test_unrecognised_name_is_unknown():
    c = classify_name("SuperSecretCipher9000")
    assert c.tier is Tier.UNKNOWN and "unrecognised" in c.flags


def test_plaintext_and_redirect():
    assert tier("plaintext") is Tier.PLAINTEXT
    assert tier("plaintext", flags={"redirect-to-https"}) is Tier.INFO


# ---------------------------------------------------------------- HNDL vs future
def test_hndl_only_for_confidentiality():
    assert classify_name("RSA_2048", usage=Usage.ENCRYPTION).hndl is True       # KMS decrypt key
    assert classify_name("RSA_2048", usage=Usage.SIGNATURE).hndl is False       # KMS signing key
    assert classify_name("x25519", usage=Usage.KEY_EXCHANGE).hndl is True
    assert classify_name("Ed25519").hndl is False                               # role inferred: signature
    assert classify_name("AES", key_size=128, usage=Usage.ENCRYPTION).hndl is False  # Grover, not Shor


def test_labels():
    assert classify_name("x25519", usage=Usage.KEY_EXCHANGE).label.startswith("CRITICAL – HNDL")
    assert classify_name("Ed25519").label.startswith("CRITICAL – future")


# ---------------------------------------------------------------- composites
def test_tls12_static_rsa_suite_is_decomposed():
    c = classify_name("TLS_RSA_WITH_AES_128_CBC_SHA")
    names = [x.name for x in c.components]
    assert names == ["RSA", "AES-128-CBC", "HMAC-SHA1"]          # CBC suite: "_SHA" is the record MAC
    assert c.tier is Tier.CRITICAL and c.hndl
    assert "no-forward-secrecy" in c.flags
    assert "classically-broken" not in c.flags                   # HMAC-SHA1 is not broken by SHA-1 collisions


def test_aead_suite_hash_is_only_the_prf():
    c = classify_name("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert c.components[-1].name == "SHA-256" and c.components[-1].role.value == "hash"
    assert classify_name("ECDHE-ECDSA-AES256-SHA384").components[-1].name == "HMAC-SHA384"
    assert "classically-broken" in classify_name("SHA1withRSA").flags      # SHA-1 in a signature IS broken


def test_tls12_ecdhe_suite_has_forward_secrecy():
    c = classify_name("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    assert [x.name for x in c.components] == ["ECDH", "RSA", "AES-256-GCM", "SHA-384"]
    assert c.hndl and "no-forward-secrecy" not in c.flags
    assert c.components[2].primitive == "ae"


def test_tls13_suite_alone_is_medium_because_of_aes128():
    c = classify_name("TLS_AES_128_GCM_SHA256")
    assert c.tier is Tier.MEDIUM and not c.hndl     # key exchange is a separate finding (key_share)


def test_jca_strings():
    c = classify_name("SHA1withRSA")
    assert [x.catalog_key for x in c.components] == ["SHA-1", "RSA"]
    assert c.tier is Tier.CRITICAL and not c.hndl
    c = classify_name("AES/ECB/PKCS5Padding", key_size=128)
    assert c.tier is Tier.MEDIUM and "insecure-mode" in c.flags
    assert tier("PBKDF2WithHmacSHA256") is Tier.SAFE
    assert tier("PBKDF2WithHmacSHA1") is Tier.MEDIUM


def test_ssh_names():
    c = classify_name("diffie-hellman-group14-sha1")
    assert c.tier is Tier.CRITICAL and c.hndl and c.components[0].bits == 2048
    assert classify_name("diffie-hellman-group1-sha1").flags >= {"weak-key-size", "classically-broken"}
    assert tier("ssh-rsa") is Tier.CRITICAL


def test_aws_names():
    c = classify_name("SYMMETRIC_DEFAULT")
    assert c.tier is Tier.SAFE and c.components[0].name == "AES-256-GCM"
    assert classify_name("RSAES_OAEP_SHA_256").hndl is True
    assert tier("ECC_NIST_P384") is Tier.CRITICAL


# ---------------------------------------------------------------- false-positive traps
@pytest.mark.parametrize("name,expected", [
    ("modes", Tier.UNKNOWN),                       # contains "des" but is not DES
    ("sntrup761x25519-sha512@openssh.com", Tier.SAFE),   # contains "x25519" but is a PQ hybrid
    ("mlkem768x25519-sha256", Tier.SAFE),
    ("X25519Kyber768Draft00", Tier.SAFE),
])
def test_false_positive_traps(name, expected):
    assert tier(name) is expected


def test_pre_standard_and_non_nist_are_flagged():
    assert "pre-standard" in classify_name("X25519Kyber768Draft00").flags
    assert "non-nist-pqc" in classify_name("sntrup761x25519-sha512").flags


# ---------------------------------------------------------------- flags + replacements
def test_rsa_1024_is_also_classically_broken():
    c = classify_name("RSA", key_size=1024, usage=Usage.SIGNATURE)
    assert {"weak-key-size", "classically-broken"} <= c.flags
    assert c.components[0].name == "RSA-1024" and c.components[0].classical_level == 80


def test_replacements_follow_the_role():
    assert "FIPS 203" in classify_name("x25519", usage=Usage.KEY_EXCHANGE).replacements[0]
    assert "FIPS 204" in classify_name("RSA_2048", usage=Usage.SIGNATURE).replacements[0]
    assert "FIPS 205" in classify_name("RSA_4096", usage=Usage.SIGNATURE, flags={"long-lived"}).replacements[0]
    assert classify_name("AES", key_size=256).replacements == []          # nothing to fix


def test_classify_fills_the_finding_and_serialises():
    f = classify(Finding(source="code", location="x.py:1", algorithm="MD5", usage=Usage.HASH))
    d = f.to_dict()
    assert d["classification"]["tier"] == "MEDIUM"
    assert d["classification"]["components"][0]["hndl"] is False
    assert "classically-broken" in d["classification"]["flags"]
