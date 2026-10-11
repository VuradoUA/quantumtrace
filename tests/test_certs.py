"""Phase 2d: certificate & key files (PEM / DER / PKCS#12 / OpenSSH) and PEM blocks pasted into code.

Certificates come from tests/fixtures/sample-infra (public data, made by make_sample_certs.py).
Private keys are generated here in a temp folder, so no secret is ever committed.
"""
import base64
import json
import struct
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from quantumtrace.catalog import load_catalog
from quantumtrace.classify import classify
from quantumtrace.models import Tier, Usage
from quantumtrace.parsers.certs import key_families, parse_cert_files, parse_pem_text
from quantumtrace.scan import detect_kind

INFRA = Path(__file__).parent / "fixtures" / "sample-infra"
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
PEM = serialization.Encoding.PEM


def scan(*paths, root=None):
    found = parse_cert_files([Path(p) for p in paths], root=root, now=NOW)
    for f in found:
        classify(f)
    return found


def by_algorithm(found):
    return {f.algorithm: f for f in found}


# ===================================================================== certificates (sample-infrastructure fixtures)
def test_certificate_chain_in_one_pem():
    found = scan(INFRA / "nginx/certs/api.pem", root=INFRA)
    assert [f.algorithm for f in found] == ["RSA", "SHA256withECDSA", "secp384r1", "SHA384withECDSA"]
    leaf_key, root_key = found[0], found[2]
    assert leaf_key.key_size == 2048 and leaf_key.usage is Usage.CERTIFICATE
    assert leaf_key.location == "nginx/certs/api.pem:1" and root_key.location.endswith(":16")
    assert leaf_key.classification.tier is Tier.CRITICAL and not leaf_key.classification.hndl
    # the root CA is valid for 15 years -> long-lived -> SLH-DSA is the recommended replacement
    assert {"ca-certificate", "long-lived", "self-signed"} <= root_key.flags
    assert any("FIPS 205" in r for r in root_key.classification.replacements)
    assert "long-lived" not in leaf_key.flags and "FIPS 204" in leaf_key.classification.replacements[0]


def test_post_quantum_certificate_is_safe():
    """ML-DSA-65 (FIPS 204) certificate: found by OID, even on a `cryptography` without ML-DSA."""
    found = scan(INFRA / "nginx/certs/vault-mldsa.pem", root=INFRA)
    assert [f.algorithm for f in found] == ["ML-DSA-65", "ML-DSA-65"]
    assert all(f.classification.tier is Tier.SAFE for f in found)


def test_der_certificate_expired_weak_sha1():
    found = scan(INFRA / "certs/legacy-sha1.crt", root=INFRA)
    key, sig = found
    assert (key.algorithm, key.key_size, sig.algorithm) == ("RSA", 1024, "SHA1withRSA")
    assert {"expired", "self-signed"} <= key.flags
    assert {"weak-key-size", "classically-broken"} <= key.classification.flags
    assert "classically-broken" in sig.classification.flags      # SHA-1 signature


def test_expiry_relative_to_now():
    found = parse_cert_files([INFRA / "nginx/certs/api.pem"], root=INFRA, now=datetime(2027, 10, 1, tzinfo=timezone.utc))
    assert "expiring-soon" in found[0].flags                      # leaf ends 2027-10-11
    found = parse_cert_files([INFRA / "nginx/certs/api.pem"], root=INFRA, now=datetime(2028, 1, 1, tzinfo=timezone.utc))
    assert "expired" in found[0].flags and "expired" not in found[2].flags


def test_ssh_public_key_file():
    found = scan(INFRA / "ssh/ssh_host_ed25519_key.pub", root=INFRA)
    assert len(found) == 1 and found[0].algorithm == "Ed25519" and found[0].usage is Usage.SIGNATURE
    assert "root@bastion" in found[0].context


def test_key_families_takes_the_leaf_certificate():
    found = scan(INFRA / "nginx/certs/api.pem", INFRA / "nginx/certs/vault-mldsa.pem", root=INFRA)
    assert key_families(found) == {"nginx/certs/api.pem": {"rsa"}, "nginx/certs/vault-mldsa.pem": {"ml-dsa-65"}}


def test_file_kinds_are_detected():
    for name in ("a.pem", "a.crt", "a.der", "a.key", "id_rsa.pub", "authorized_keys", "known_hosts", "id_ed25519",
                 "ssh_host_rsa_key", "store.p12"):
        assert detect_kind(Path(name)) == "cert", name


# ===================================================================== private keys (generated, never committed)
@pytest.fixture()
def keys(tmp_path):
    rsa1024 = rsa.generate_private_key(65537, 1024)
    (tmp_path / "legacy.key").write_bytes(rsa1024.private_bytes(
        PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    (tmp_path / "protected.key").write_bytes(rsa1024.private_bytes(
        PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.BestAvailableEncryption(b"pw")))
    (tmp_path / "pkcs8-enc.key").write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw")))
    ed = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "id_ed25519").write_bytes(ed.private_bytes(
        PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
    return tmp_path, rsa1024


def test_private_keys_are_reported_without_their_material(keys):
    folder, rsa1024 = keys
    found = scan(*sorted(folder.iterdir()), root=folder)
    by_file = {}
    for f in found:
        by_file.setdefault(f.asset, []).append(f)

    legacy = by_file["legacy.key"][0]
    assert (legacy.algorithm, legacy.key_size) == ("RSA", 1024)
    assert {"private-key", "unencrypted-private-key"} <= legacy.flags
    assert "weak-key-size" in legacy.classification.flags

    prot = by_file["protected.key"]
    assert prot[0].algorithm == "RSA" and "encrypted-private-key" in prot[0].flags
    assert prot[1].algorithm == "AES-256-CBC" and "key-file-encryption" in prot[1].flags   # legacy DEK-Info

    assert "encrypted-private-key" in by_file["pkcs8-enc.key"][0].flags
    assert by_file["id_ed25519"][0].algorithm == "Ed25519"

    # the key material never reaches the report
    secret = rsa1024.private_bytes(PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption()).decode().splitlines()[1]
    assert secret not in json.dumps([f.to_dict() for f in found])


def test_encrypted_openssh_key_type_is_readable_without_password(tmp_path):
    """openssh-key-v1 keeps the public key in clear text: build one by hand with an
    encrypted (here: random) private section and check we still read type + size."""
    pub = rsa.generate_private_key(65537, 3072).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[1]
    s = lambda b: struct.pack(">I", len(b)) + b                       # noqa: E731
    blob = b"openssh-key-v1\0" + s(b"aes256-ctr") + s(b"bcrypt") + s(b"\0" * 24) + struct.pack(">I", 1) \
        + s(base64.b64decode(pub)) + s(b"\x8f" * 64)
    body = base64.encodebytes(blob).decode()
    (tmp_path / "id_rsa").write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}-----END OPENSSH PRIVATE KEY-----\n")
    f = scan(tmp_path / "id_rsa", root=tmp_path)[0]
    assert (f.algorithm, f.key_size) == ("RSA", 3072)
    assert "encrypted-private-key" in f.flags and "aes256-ctr" in f.context


def test_key_and_certificate_with_same_name_are_linked(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime(2026, 1, 1)).not_valid_after(datetime(2027, 1, 1))
            .sign(key, hashes.SHA256()))
    (tmp_path / "svc.crt").write_bytes(cert.public_bytes(PEM))
    (tmp_path / "svc.key").write_bytes(key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    found = scan(tmp_path / "svc.crt", tmp_path / "svc.key", root=tmp_path)
    assert all(f.related for f in found)
    assert {f.algorithm for f in found} == {"secp256r1", "SHA256withECDSA"}


def test_pkcs12_with_and_without_password(tmp_path):
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "store")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime(2026, 1, 1)).not_valid_after(datetime(2027, 1, 1))
            .sign(key, hashes.SHA256()))
    (tmp_path / "open.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"store", key, cert, None, serialization.NoEncryption()))
    (tmp_path / "locked.pfx").write_bytes(pkcs12.serialize_key_and_certificates(
        b"store", key, cert, None, serialization.BestAvailableEncryption(b"pw")))
    found = scan(tmp_path / "open.p12", tmp_path / "locked.pfx", root=tmp_path)
    opened = [f for f in found if f.asset == "open.p12"]
    assert [f.algorithm for f in opened] == ["RSA", "RSA", "SHA256withRSA"]       # key, cert key, cert signature
    locked = [f for f in found if f.asset == "locked.pfx"]
    assert len(locked) == 1 and "password-protected" in locked[0].flags
    assert locked[0].classification.tier is Tier.UNKNOWN


def test_dh_parameters_file(tmp_path):
    oakley2 = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
                  "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
                  "0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pem = dh.DHParameterNumbers(oakley2, 2).parameters().parameter_bytes(
            PEM, serialization.ParameterFormat.PKCS3)
    (tmp_path / "dhparam.pem").write_bytes(pem)
    f = scan(tmp_path / "dhparam.pem", root=tmp_path)[0]
    assert (f.algorithm, f.key_size, f.usage) == ("DH", 1024, Usage.KEY_EXCHANGE)
    assert f.classification.hndl and "weak-key-size" in f.classification.flags


def test_authorized_keys_and_known_hosts(tmp_path):
    rsa_pub = rsa.generate_private_key(65537, 2048).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    ed_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    (tmp_path / "authorized_keys").write_text(f"# ops team\n{rsa_pub} alice@laptop\nfrom=\"10.0.0.0/8\" {ed_pub} ci\n")
    (tmp_path / "known_hosts").write_text(f"git.example.lab,10.0.0.5 {ed_pub}\n")
    found = scan(tmp_path / "authorized_keys", tmp_path / "known_hosts", root=tmp_path)
    assert [(f.location, f.algorithm, f.key_size) for f in found] == [
        ("authorized_keys:2", "RSA", 2048), ("authorized_keys:3", "Ed25519", None), ("known_hosts:1", "Ed25519", None)]
    assert "authorized-key" in found[0].flags and "known-host-key" in found[2].flags


# ===================================================================== PEM blocks inside source code
def test_private_key_pasted_into_source_code():
    cat = load_catalog()
    key = rsa.generate_private_key(65537, 2048).private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    escaped = key.replace("\n", "\\n")
    code = f'import os\nKEY = """{key}"""\n\nOTHER = "{escaped}"\n'
    found = parse_pem_text(code, "app/settings.py", cat, NOW, source="code", embedded=True)
    assert [f.location for f in found] == ["app/settings.py:2", f"app/settings.py:{code.count(chr(10), 0, code.index('OTHER')) + 1}"]
    for f in found:
        classify(f)
        assert f.source == "code" and f.algorithm == "RSA" and f.key_size == 2048
        assert {"embedded-pem", "hardcoded-key", "private-key"} <= f.flags
        assert key.splitlines()[1] not in f.evidence + f.context


def test_garbage_pem_block_is_reported_not_fatal():
    cat = load_catalog()
    found = parse_pem_text("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n",
                           "bad.pem", cat, NOW)
    assert len(found) == 1 and "unparseable" in found[0].flags


def test_scan_finds_certificate_pasted_into_sample_code():
    from quantumtrace.scan import scan_path

    found = [f for f in scan_path(INFRA, now=NOW).findings if f.asset == "app-python/app.py" and "embedded-pem" in f.flags]
    assert [(f.source, f.location, f.algorithm) for f in found] == [
        ("code", "app-python/app.py:10", "secp384r1"), ("code", "app-python/app.py:10", "SHA384withECDSA")]
    assert "ca-certificate" in found[0].flags
