"""Data model shared by every part of QuantumTrace.

A parser creates one `Finding` per occurrence it sees (decision 2: inventory
everything). The classifier then fills in `finding.classification`.
"""
from __future__ import annotations

import itertools
from dataclasses import asdict, dataclass, field
from enum import Enum


class Tier(str, Enum):
    """Risk tier. The first three are the challenge's official tiers and the
    only ones that count in the Quantum Risk Score."""
    CRITICAL = "CRITICAL"     # Shor breaks it
    MEDIUM = "MEDIUM"         # Grover weakens it below 256-bit strength
    SAFE = "SAFE"             # AES-256, SHA-384, ML-KEM, ...
    PLAINTEXT = "PLAINTEXT"   # no crypto at all
    UNKNOWN = "UNKNOWN"       # crypto found, but not enough info (e.g. AES, key size unknown)
    INFO = "INFO"             # worth listing, not a risk (e.g. HTTP that only redirects to HTTPS)

    @property
    def severity(self) -> int:
        """Higher = worse. Used to pick the worst component of a composite."""
        return _SEVERITY[self]

    @property
    def scored(self) -> bool:
        return self in (Tier.CRITICAL, Tier.MEDIUM, Tier.SAFE)


_SEVERITY = {Tier.SAFE: 0, Tier.INFO: 1, Tier.UNKNOWN: 2, Tier.MEDIUM: 3,
             Tier.CRITICAL: 4, Tier.PLAINTEXT: 5}


class Usage(str, Enum):
    """What the crypto is used FOR. Decides HNDL exposure and the replacement."""
    KEY_EXCHANGE = "key_exchange"   # TLS/SSH key agreement, key transport
    ENCRYPTION = "encryption"       # encrypting data (incl. KMS ENCRYPT_DECRYPT keys)
    SIGNATURE = "signature"         # signing / verifying, authentication
    CERTIFICATE = "certificate"     # X.509 certificate key / signature
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    PROTOCOL = "protocol"           # a whole TLS cipher suite / SSH algorithm string
    LIBRARY = "library"             # a crypto library declared in a dependency manifest (inventory)
    UNKNOWN = "unknown"


# Roles that protect CONFIDENTIALITY: if Shor breaks them, recorded data can be
# decrypted later -> Harvest Now, Decrypt Later.
CONFIDENTIALITY_ROLES = {Usage.KEY_EXCHANGE, Usage.ENCRYPTION}


@dataclass
class ComponentResult:
    """One resolved algorithm inside a finding (a composite like a TLS cipher
    suite has several)."""
    id: str                          # stable id, e.g. "rsa-1024", "aes-128-ecb"
    name: str                        # display name, e.g. "RSA-1024"
    catalog_key: str | None          # entry in catalog.yaml, None if unrecognised
    kind: str
    role: Usage
    tier: Tier
    threat: str                      # shor | grover | none
    primitive: str                   # CycloneDX primitive
    bits: int | None = None
    mode: str | None = None
    oid: str | None = None
    nist_quantum_level: int | None = None
    classical_level: int | None = None
    replacement: str | None = None
    standard: str | None = None
    flags: set[str] = field(default_factory=set)

    @property
    def hndl(self) -> bool:
        return self.threat == "shor" and self.role in CONFIDENTIALITY_ROLES


@dataclass
class Classification:
    tier: Tier                       # worst component
    hndl: bool                       # any Shor-breakable component protecting confidentiality
    components: list[ComponentResult]
    flags: set[str] = field(default_factory=set)
    replacements: list[str] = field(default_factory=list)   # "ML-DSA-65 (FIPS 204)"

    @property
    def label(self) -> str:
        """Human label, e.g. 'CRITICAL – HNDL' vs 'CRITICAL – future'."""
        if self.tier is Tier.CRITICAL:
            return "CRITICAL – HNDL (exposed now)" if self.hndl else "CRITICAL – future (forgery)"
        return self.tier.value


_ids = itertools.count(1)


@dataclass
class Finding:
    """One occurrence of cryptography (or of its absence) in one input."""
    source: str                      # "pcap" | "code" | "cloud" | "config"
    location: str                    # exact place: "file.py:6", "network.pcap#frame 412", "kms.json:$.Keys[2]"
    algorithm: str                   # raw name as observed, e.g. "SHA1withRSA"
    usage: Usage = Usage.UNKNOWN
    asset: str = ""                  # the thing that uses it: file, host:port, ARN
    key_size: int | None = None      # bits, if the parser knows it
    mode: str | None = None          # cipher mode, if known (ecb, gcm, ...)
    evidence: str = ""               # the exact text / field that matched
    context: str = ""                # e.g. "tls1.2 negotiated", "ssh kex offered"
    flags: set[str] = field(default_factory=set)   # parser-level facts: expired, hardcoded-key, ...
    related: list[str] = field(default_factory=list)  # other assets it is linked to (e.g. cert ARN <-> listener ARN)
    library: str = ""                # crypto library / API that provides it (hashlib, javax.crypto, crypto/aes, ...)
    purl: str = ""                   # package URL of that library when a manifest declares it (pkg:pypi/cryptography@46.0.5)
    version: str = ""                # declared library version: exact "46.0.5" or a range ">=42" (manifests only)
    details: dict[str, str] = field(default_factory=dict)
    # structured facts the CBOM needs (Phase 3), e.g.
    #   protocol: tls | ssh | http ...   tls_version / tls_versions, suite_id, group_id, sigscheme_id, ssh_role
    #   cert: certificate identity (SHA-256 fingerprint / ARN), cert_part: public-key | signature,
    #         subject, issuer, not_before, not_after, serial
    #   key: key identity, key_type: private-key | public-key | secret-key, key_state, created, expires
    confidence: float = 1.0
    classification: Classification | None = None
    id: str = field(default_factory=lambda: f"f-{next(_ids):04d}")

    def to_dict(self) -> dict:
        """JSON-friendly dict (enums -> strings, sets -> sorted lists)."""
        d = _jsonable(asdict(self))
        if self.classification is not None:          # add the computed properties too
            d["classification"]["label"] = self.classification.label
            for cd, comp in zip(d["classification"]["components"], self.classification.components):
                cd["hndl"] = comp.hndl
        return d


def _jsonable(obj):
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, set):
        return sorted(_jsonable(v) for v in obj)
    return obj
