"""Shared X.509 / key helpers, used by the PCAP parser (certificates on the wire) and the
certificate & key file parser (PEM / DER / SSH keys on disk).

Everything is decoded with the `cryptography` library, so the result does not depend on
the tshark version (tshark 4.6 leaves some X.509 fields empty).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..catalog import Catalog

EXPIRING_SOON = timedelta(days=30)
LONG_LIVED = timedelta(days=5 * 365)          # >= 5 years of validity: roots / intermediates / device certs


def key_info(pk, cat: Catalog | None = None, oid: str | None = None) -> tuple[str | None, int | None, str]:
    """Public or private key object -> (catalog name, bits, family).

    family is a short word used to match TLS cipher suites to the certificate:
    rsa | ec | dsa | ed25519 | ed448 | x25519 | x448 | pqc | unknown.
    Unknown key types (e.g. ML-DSA on an older `cryptography`) fall back to the OID."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

    if pk is not None:
        if isinstance(pk, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
            return "RSA", pk.key_size, "rsa"
        if isinstance(pk, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
            return pk.curve.name, pk.key_size, "ec"                  # "secp256r1"
        if isinstance(pk, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
            return "DSA", pk.key_size, "dsa"
        if type(pk).__name__.startswith("DH"):          # (finite-field DH is deprecated in `cryptography`)
            return "DH", pk.key_size, "dh"
        for classes, name in (((ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey), "Ed25519"),
                              ((ed448.Ed448PublicKey, ed448.Ed448PrivateKey), "Ed448"),
                              ((x25519.X25519PublicKey, x25519.X25519PrivateKey), "X25519"),
                              ((x448.X448PublicKey, x448.X448PrivateKey), "X448")):
            if isinstance(pk, classes):
                return name, None, name.lower()
        cls = type(pk).__name__.upper()                               # MLDSA65PublicKey, MLKEM768PrivateKey
        for prefix, label in (("MLDSA", "ML-DSA-"), ("MLKEM", "ML-KEM-"), ("SLHDSA", "SLH-DSA")):
            if cls.startswith(prefix):
                digits = "".join(ch for ch in cls[len(prefix):] if ch.isdigit())
                return (label + digits if label.endswith("-") and digits else label.rstrip("-")), None, "pqc"
    if oid and cat is not None and oid in cat.x509_oids:
        name = cat.x509_oids[oid]
        fam = "pqc" if name.startswith(("ML-", "SLH-")) else name.lower().replace("ecdsa", "ec")
        return name, None, fam
    return (f"OID {oid}" if oid else None), None, "unknown"


@dataclass
class CertFacts:
    key_name: str
    key_bits: int | None
    key_family: str
    key_oid: str
    sig_name: str
    sig_oid: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    flags: set[str] = field(default_factory=set)
    fingerprint: str = ""             # SHA-256 of the DER encoding: the certificate's identity in the CBOM
    serial: str = ""

    def context(self) -> str:
        return f"{self.subject}, issued by {self.issuer}, valid {self.not_before:%Y-%m-%d} to {self.not_after:%Y-%m-%d}"

    def details(self, part: str) -> dict[str, str]:
        """Finding.details for the 'public-key' or the 'signature' finding of this certificate."""
        return {"cert": f"sha256:{self.fingerprint}", "cert_part": part, "subject": self.subject,
                "issuer": self.issuer, "not_before": _iso(self.not_before), "not_after": _iso(self.not_after),
                "serial": self.serial}


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def certificate_facts(cert, cat: Catalog, now: datetime) -> CertFacts:
    """An x509.Certificate -> what QuantumTrace reports about it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    key_oid = getattr(cert, "public_key_algorithm_oid", None)      # cryptography >= 43
    key_oid = key_oid.dotted_string if key_oid is not None else ""
    try:
        pk = cert.public_key()
    except Exception:                                              # unsupported key type in this `cryptography`
        pk = None
    key_name, bits, family = key_info(pk, cat, key_oid or None)
    sig_oid = cert.signature_algorithm_oid.dotted_string
    not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc

    flags: set[str] = set()
    if not_after < now:
        flags.add("expired")
    elif not_after < now + EXPIRING_SOON:
        flags.add("expiring-soon")
    if not_before > now:
        flags.add("not-yet-valid")
    if cert.issuer == cert.subject:
        flags.add("self-signed")
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            flags.add("ca-certificate")
    except (x509.ExtensionNotFound, ValueError):
        pass
    if not_after - not_before >= LONG_LIVED:
        flags.add("long-lived")                    # the classifier then recommends SLH-DSA (FIPS 205)
    return CertFacts(key_name=key_name or f"OID {key_oid}", key_bits=bits, key_family=family, key_oid=key_oid,
                     sig_name=cat.x509_oids.get(sig_oid, f"OID {sig_oid}"), sig_oid=sig_oid,
                     subject=cert.subject.rfc4514_string() or "(empty subject)",
                     issuer=cert.issuer.rfc4514_string() or "(empty issuer)",
                     not_before=not_before, not_after=not_after, flags=flags,
                     fingerprint=cert.fingerprint(hashes.SHA256()).hex(), serial=format(cert.serial_number, "x"))
