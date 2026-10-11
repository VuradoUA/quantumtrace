"""Re-creates the PUBLIC certificate / key files of tests/fixtures/sample-infra (run once; needs
cryptography >= 48 for the ML-DSA certificate). Private keys are thrown away: no secret
ever lands in the repository. The test suite only reads the files this script wrote.

    python tests/fixtures/make_sample_certs.py
"""
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, rsa
from cryptography.x509.oid import NameOID

INFRA = Path(__file__).parent / "sample-infra"
PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, issuer, key, signer, start, end, ca=False, algo=hashes.SHA256()):
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(end)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(subject)]), critical=False)
    return b.sign(signer, algo)


d = dt.datetime
# nginx/certs/api.pem: RSA-2048 leaf (1 year) + its ECDSA P-384 root CA (15 years -> long-lived)
root_key = ec.generate_private_key(ec.SECP384R1())
root = cert("Sample infrastructure Root CA", "Sample infrastructure Root CA", root_key, root_key, d(2026, 1, 1), d(2041, 1, 1), ca=True, algo=hashes.SHA384())
leaf_key = rsa.generate_private_key(65537, 2048)
leaf = cert("api.example.lab", "Sample infrastructure Root CA", leaf_key, root_key, d(2026, 10, 11), d(2027, 10, 11))
(INFRA / "nginx/certs").mkdir(parents=True, exist_ok=True)
(INFRA / "nginx/certs/api.pem").write_bytes(leaf.public_bytes(PEM) + root.public_bytes(PEM))

# nginx/certs/vault-mldsa.pem: post-quantum ML-DSA-65 self-signed certificate (FIPS 204)
pq_key = mldsa.MLDSA65PrivateKey.generate()
pq = cert("vault.example.lab", "vault.example.lab", pq_key, pq_key, d(2026, 10, 11), d(2028, 10, 11), algo=None)
(INFRA / "nginx/certs/vault-mldsa.pem").write_bytes(pq.public_bytes(PEM))

# certs/legacy-sha1.crt (DER, RSA-1024, SHA1withRSA, valid 2019-01-01..2021-01-01) is NOT made here:
# current `cryptography` refuses to sign with SHA-1, so it was made with the openssl CLI:
#   openssl genrsa -out k.pem 1024
#   openssl req -new -key k.pem -subj /CN=legacy.example.lab -out r.csr
#   openssl ca -batch -config ca.cnf -selfsign -keyfile k.pem -in r.csr -md sha1 \
#       -startdate 20190101000000Z -enddate 20210101000000Z -out c.pem
#   openssl x509 -in c.pem -outform DER -out legacy-sha1.crt

# ssh/ssh_host_ed25519_key.pub: the sshd host key (public half only)
host = ed25519.Ed25519PrivateKey.generate().public_key()
(INFRA / "ssh").mkdir(exist_ok=True)
(INFRA / "ssh/ssh_host_ed25519_key.pub").write_bytes(
    host.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH) + b" root@bastion\n")
print("written to", INFRA)
