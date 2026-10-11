"""Certificate & key files (Phase 2d): PEM, DER, PKCS#12, OpenSSH keys, authorized_keys / known_hosts.

What it reports, one Finding per object found:
  certificate      key algorithm + size, signature algorithm   (usage certificate)
                   flags: expired, expiring-soon, self-signed, ca-certificate, long-lived, ...
  CSR              same as a certificate + flag csr
  private key      key algorithm + size; flags private-key + unencrypted-private-key / encrypted-private-key
                   (the key material itself is NEVER copied into the report)
  public key       key algorithm + size (SSH keys: usage signature)
  DH parameters    DH + prime size (nginx/Apache ssl_dhparam files)
  PEM file encryption (legacy "DEK-Info: DES-EDE3-CBC") -> the cipher protecting the key file

The same code also finds PEM blocks embedded in source code / config files
(`parse_pem_text`), e.g. a private key pasted into a Python string -> flag hardcoded-key.
"""
from __future__ import annotations

import base64
import re
import struct
import warnings
from datetime import datetime, timezone
from pathlib import Path

from ..catalog import Catalog, load_catalog
from ..models import Finding, Usage
from .x509util import certificate_facts, key_info

EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".csr", ".p12", ".pfx", ".p7b", ".p7c"}
FILENAMES = {"authorized_keys", "authorized_keys2", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
             "id_ecdsa_sk", "id_ed25519_sk"}
HOST_KEY = re.compile(r"^ssh_host_\w+_key$")
PEM = re.compile(r"-----BEGIN ([A-Z0-9 .]+)-----\r?\n(.*?)-----END \1-----", re.S)
SSH_KEY_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                 "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
SSH_LINE = re.compile(r"(?:^|\s)(" + "|".join(re.escape(t) for t in SSH_KEY_TYPES) + r")\s+(AAAA[0-9A-Za-z+/]+=*)(?:\s+(\S.*))?$")
SSH_TYPE_NAMES = {"ssh-rsa": "RSA", "ssh-dss": "DSA", "ssh-ed25519": "Ed25519", "ssh-ed448": "Ed448",
                  "ecdsa-sha2-nistp256": "secp256r1", "ecdsa-sha2-nistp384": "secp384r1",
                  "ecdsa-sha2-nistp521": "secp521r1", "sk-ssh-ed25519@openssh.com": "Ed25519",
                  "sk-ecdsa-sha2-nistp256@openssh.com": "secp256r1"}
MAX_BYTES = 5 * 1024 * 1024


def is_cert_file(path: Path) -> bool:
    name = path.name
    return path.suffix.lower() in EXTENSIONS or name in FILENAMES or bool(HOST_KEY.match(name))


# ====================================================================== entry points
def parse_cert_files(paths: list[Path], root: Path | None = None, now: datetime | None = None,
                     catalog: Catalog | None = None) -> list[Finding]:
    cat = catalog or load_catalog()
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    for p in paths:
        rel = str(Path(p).relative_to(root)) if root else Path(p).name
        try:
            data = Path(p).read_bytes()[:MAX_BYTES]
        except OSError:
            continue
        if b"-----BEGIN " in data:
            out += parse_pem_text(data.decode("utf-8", "replace"), rel, cat, now, source="config")
        elif Path(p).suffix.lower() in (".p12", ".pfx"):
            out += _pkcs12(data, rel, cat, now)
        elif _looks_like_ssh_keys(data):
            out += _ssh_public_keys(data.decode("utf-8", "replace"), rel, cat, Path(p).name)
        else:
            out += _der(data, rel, cat, now)
    _link_keys_to_certificates(out)
    return out


def parse_pem_text(text: str, rel: str, cat: Catalog, now: datetime, source: str = "config",
                   embedded: bool = False) -> list[Finding]:
    """Every PEM block in a text. `embedded` = the text is source code / config, not a key file."""
    out = []
    scan = text
    if embedded and "\\n-----END" in text:          # "-----BEGIN ...-----\nMIIE...\n-----END ...-----" in a string literal
        scan = text.replace("\\n", "\n")
    seen: dict[str, int] = {}
    for m in PEM.finditer(scan):
        label, body = m.group(1), m.group(2)
        marker = f"-----BEGIN {label}-----"
        pos = -1
        for _ in range(seen.get(marker, 0) + 1):       # the k-th BEGIN marker in the ORIGINAL text -> its line
            pos = text.find(marker, pos + 1)
        seen[marker] = seen.get(marker, 0) + 1
        line = text.count("\n", 0, max(pos, 0)) + 1
        common = dict(source=source, location=f"{rel}:{line}", asset=rel)
        lines = [ln.strip().strip('"\'') for ln in body.splitlines()]   # indentation / quotes inside source code
        block = (f"{marker}\n" + "\n".join(lines).strip("\n") + f"\n-----END {label}-----\n").encode()
        found = _pem_block(label, body, block, cat, now, common)
        if embedded:
            for f in found:
                f.flags.add("embedded-pem")
                if "private-key" in f.flags:
                    f.flags.add("hardcoded-key")
        out += found
    if not embedded and not out:                      # a .pub / authorized_keys that also had a PEM header?
        out += _ssh_public_keys(text, rel, cat, Path(rel).name)
    return out


# ====================================================================== PEM blocks
def _pem_block(label: str, body: str, block: bytes, cat: Catalog, now: datetime, common: dict) -> list[Finding]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    ev = f"-----BEGIN {label}-----"
    try:
        if label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
            return _certificate(x509.load_pem_x509_certificate(block.replace(b"TRUSTED ", b"")), cat, now, common, ev)
        if label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
            csr = x509.load_pem_x509_csr(block.replace(b"NEW CERTIFICATE", b"CERTIFICATE"))
            return _csr(csr, cat, common, ev)
        if label in ("PKCS7", "CERTIFICATES"):
            from cryptography.hazmat.primitives.serialization import pkcs7
            out = []
            for c in pkcs7.load_pem_pkcs7_certificates(block):
                out += _certificate(c, cat, now, common, ev)
            return out
        if label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
            return [_key_finding(serialization.load_pem_public_key(block), cat, common, ev, "public key", set())]
        if label in ("DH PARAMETERS", "X9.42 DH PARAMETERS"):
            with warnings.catch_warnings():            # cryptography deprecates finite-field DH; we only read it
                warnings.simplefilter("ignore")
                bits = serialization.load_pem_parameters(block).parameter_numbers().p.bit_length()
            return [Finding(algorithm="DH", usage=Usage.KEY_EXCHANGE, key_size=bits, evidence=ev,
                            context=f"Diffie-Hellman parameters ({bits}-bit prime), e.g. an ssl_dhparam file",
                            **common)]
        if label.endswith("PRIVATE KEY"):
            return _private_key(label, body, block, cat, common, ev)
    except Exception as e:                             # malformed / unsupported: report, never crash the scan
        return [Finding(algorithm=f"unparseable {label.lower()}", usage=Usage.UNKNOWN, evidence=ev,
                        context=f"PEM block could not be decoded: {type(e).__name__}", flags={"unparseable"},
                        confidence=0.3, **common)]
    return []                                          # PGP, SSH2 PUBLIC KEY, ... : not ours


def _certificate(cert, cat: Catalog, now: datetime, common: dict, ev: str) -> list[Finding]:
    facts = certificate_facts(cert, cat, now)
    ctx = f"certificate {facts.context()}"
    return [
        Finding(algorithm=facts.key_name, usage=Usage.CERTIFICATE, key_size=facts.key_bits, flags=set(facts.flags),
                context=ctx, evidence=f"{ev} public key {facts.key_oid or '?'}", details=facts.details("public-key"),
                **common),
        Finding(algorithm=facts.sig_name, usage=Usage.CERTIFICATE, flags=set(facts.flags), context=ctx,
                evidence=f"{ev} signatureAlgorithm {facts.sig_oid}", details=facts.details("signature"), **common),
    ]


def _csr(csr, cat: Catalog, common: dict, ev: str) -> list[Finding]:
    key_oid = getattr(csr, "public_key_algorithm_oid", None)
    try:
        pk = csr.public_key()
    except Exception:
        pk = None
    name, bits, _ = key_info(pk, cat, key_oid.dotted_string if key_oid is not None else None)
    sig_oid = csr.signature_algorithm_oid.dotted_string
    ctx = f"certificate signing request for {csr.subject.rfc4514_string()}"
    return [Finding(algorithm=name or "unknown", usage=Usage.CERTIFICATE, key_size=bits, flags={"csr"},
                    context=ctx, evidence=f"{ev} public key", **common),
            Finding(algorithm=cat.x509_oids.get(sig_oid, f"OID {sig_oid}"), usage=Usage.CERTIFICATE, flags={"csr"},
                    context=ctx, evidence=f"{ev} signatureAlgorithm {sig_oid}", **common)]


def _key_finding(key, cat: Catalog, common: dict, ev: str, what: str, flags: set[str],
                 usage: Usage = Usage.UNKNOWN, extra_ctx: str = "") -> Finding:
    name, bits, _ = key_info(key, cat)
    return Finding(algorithm=name or "unknown", usage=usage, key_size=bits, flags=set(flags), evidence=ev,
                   context=f"{what} ({name}{f' {bits}-bit' if bits else ''}){extra_ctx}",
                   details=_key_details(common, "private-key" if "private-key" in flags else "public-key"), **common)


def _key_details(common: dict, key_type: str) -> dict[str, str]:
    """A key's identity in the CBOM is where it was found (file:line)."""
    return {"key": common["location"], "key_type": key_type}


def _private_key(label: str, body: str, block: bytes, cat: Catalog, common: dict, ev: str) -> list[Finding]:
    from cryptography.hazmat.primitives import serialization

    ev = f"{ev} (key material not shown)"
    flags = {"private-key"}
    out: list[Finding] = []
    if label == "OPENSSH PRIVATE KEY":
        name, bits, cipher = _openssh_private_header(body)
        flags.add("unencrypted-private-key" if cipher == "none" else "encrypted-private-key")
        out.append(Finding(algorithm=name, usage=Usage.SIGNATURE, key_size=bits, flags=flags, evidence=ev,
                           context=f"OpenSSH private key ({name}{f' {bits}-bit' if bits else ''}), "
                                   f"{'not encrypted' if cipher == 'none' else f'encrypted with {cipher}'}",
                           details=_key_details(common, "private-key"), **common))
        return out
    dek = re.search(r"DEK-Info:\s*([A-Za-z0-9-]+)", body)
    if dek:                                            # legacy OpenSSL PEM encryption of the key file itself
        out.append(Finding(algorithm=dek.group(1), usage=Usage.ENCRYPTION, flags={"key-file-encryption"},
                           evidence=f"DEK-Info: {dek.group(1)}", context="cipher protecting the private key file (legacy PEM encryption)",
                           **common))
    try:
        key = serialization.load_pem_private_key(block, password=None)
        flags.add("unencrypted-private-key")
        out.insert(0, _key_finding(key, cat, common, ev, "private key, NOT encrypted", flags))
    except TypeError:                                  # encrypted: the type is only in the label (if at all)
        flags.add("encrypted-private-key")
        name = {"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "ECDSA", "DSA PRIVATE KEY": "DSA"}.get(label, "encrypted-private-key")
        out.insert(0, Finding(algorithm=name, usage=Usage.UNKNOWN, flags=flags, evidence=ev, confidence=0.7,
                              context=f"private key, encrypted (type from the PEM label: {label})",
                              details=_key_details(common, "private-key"), **common))
    return out


def _openssh_private_header(body: str) -> tuple[str, int | None, str]:
    """The openssh-key-v1 format keeps the PUBLIC key unencrypted in its header, so the key
    type and size are readable even when the private part is encrypted (no password needed)."""
    from cryptography.hazmat.primitives import serialization

    raw = base64.b64decode("".join(body.split()))
    if not raw.startswith(b"openssh-key-v1\0"):
        raise ValueError("not an openssh-key-v1 blob")
    pos = len(b"openssh-key-v1\0")

    def read_string() -> bytes:
        nonlocal pos
        (n,) = struct.unpack(">I", raw[pos:pos + 4])
        pos += 4
        val = raw[pos:pos + n]
        pos += n
        return val

    cipher = read_string().decode()
    read_string()                                      # kdf name
    read_string()                                      # kdf options
    pos += 4                                           # number of keys
    blob = read_string()
    key_type = blob[4:4 + struct.unpack(">I", blob[:4])[0]].decode()
    try:
        pub = serialization.load_ssh_public_key(key_type.encode() + b" " + base64.b64encode(blob))
        name, bits, _ = key_info(pub)
    except Exception:                                  # e.g. sk-* security keys
        name, bits = SSH_TYPE_NAMES.get(key_type, key_type), None
    return name or key_type, bits, cipher


# ====================================================================== SSH public keys
def _looks_like_ssh_keys(data: bytes) -> bool:
    head = data[:4096].decode("utf-8", "replace")
    return any(t in head for t in SSH_KEY_TYPES)


def _ssh_public_keys(text: str, rel: str, cat: Catalog, filename: str) -> list[Finding]:
    from cryptography.hazmat.primitives import serialization

    kind = {"authorized_keys": "authorized key", "authorized_keys2": "authorized key",
            "known_hosts": "known host key"}.get(filename, "SSH public key")
    flag = {"authorized key": "authorized-key", "known host key": "known-host-key"}.get(kind)
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        m = SSH_LINE.search(line)
        if not m:
            continue
        key_type, b64, comment = m.group(1), m.group(2), (m.group(3) or "").strip()
        flags = {flag} if flag else set()
        if key_type.startswith("sk-"):
            flags.add("security-key")
        try:
            name, bits, _ = key_info(serialization.load_ssh_public_key(f"{key_type} {b64}".encode()), cat)
        except Exception:
            name, bits = SSH_TYPE_NAMES[key_type], None
        out.append(Finding(source="config", location=f"{rel}:{i}", asset=rel, algorithm=name, usage=Usage.SIGNATURE,
                           key_size=bits, flags=flags, evidence=f"{key_type} AAAA... ({len(b64)} base64 chars)",
                           details={"key": f"{rel}:{i}", "key_type": "public-key"},
                           context=f"{kind} {key_type}{f' {bits}-bit' if bits else ''}"
                                   + (f" ({comment[:60]})" if comment else "")))
    return out


# ====================================================================== binary formats
def _der(data: bytes, rel: str, cat: Catalog, now: datetime) -> list[Finding]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    common = dict(source="config", location=rel, asset=rel)
    ev = "DER-encoded file"
    for loader, kind in ((x509.load_der_x509_certificate, "cert"), (x509.load_der_x509_csr, "csr"),
                         (serialization.load_der_public_key, "public"), (serialization.load_der_private_key, "private")):
        try:
            obj = loader(data, None) if kind == "private" else loader(data)
        except Exception:
            continue
        if kind == "cert":
            return _certificate(obj, cat, now, common, ev)
        if kind == "csr":
            return _csr(obj, cat, common, ev)
        if kind == "public":
            return [_key_finding(obj, cat, common, ev, "public key", set())]
        return [_key_finding(obj, cat, common, f"{ev} (key material not shown)", "private key, NOT encrypted",
                             {"private-key", "unencrypted-private-key"})]
    return []


def _pkcs12(data: bytes, rel: str, cat: Catalog, now: datetime) -> list[Finding]:
    from cryptography.hazmat.primitives.serialization import pkcs12

    common = dict(source="config", location=rel, asset=rel)
    for password in (None, b""):
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(data, password)
        except (ValueError, TypeError):
            continue
        out = []
        if key is not None:
            out.append(_key_finding(key, cat, common, "PKCS#12 keystore (key material not shown)",
                                    "private key in a PKCS#12 keystore without password",
                                    {"private-key", "unencrypted-private-key", "keystore"}))
        for c in ([cert] if cert else []) + list(extra or []):
            out += _certificate(c, cat, now, common, "PKCS#12 keystore")
        return out
    return [Finding(algorithm="pkcs12-keystore", usage=Usage.UNKNOWN, flags={"keystore", "password-protected"},
                    evidence="PKCS#12 keystore", context="password-protected keystore: contents not readable",
                    confidence=0.3, **common)]


# ====================================================================== traceability
def _link_keys_to_certificates(findings: list[Finding]) -> None:
    """A private key file and the certificate file it belongs to refer to each other (by
    matching algorithm + size in the same folder is too weak, so: same file stem)."""
    by_stem: dict[tuple[str, str], set[str]] = {}
    for f in findings:
        p = Path(f.asset)
        by_stem.setdefault((str(p.parent), p.stem), set()).add(f.asset)
    for f in findings:
        p = Path(f.asset)
        for other in sorted(by_stem.get((str(p.parent), p.stem), set()) - {f.asset}):
            if other not in f.related:
                f.related.append(other)


def key_families(findings: list[Finding]) -> dict[str, set[str]]:
    """certificate file -> key families of the certificates in it (rsa / ec / ...).
    Used by the TLS config parsers to drop cipher suites the server's certificate cannot use."""
    out: dict[str, set[str]] = {}
    for f in findings:                                 # the FIRST certificate of a file is the server's own (leaf first)
        if f.asset in out or f.usage is not Usage.CERTIFICATE or "csr" in f.flags or " public key " not in f.evidence:
            continue
        fam = ("rsa" if f.algorithm == "RSA" else "dsa" if f.algorithm == "DSA" else
               "ec" if f.algorithm.lower().startswith(("secp", "prime", "ecdsa", "brainpool")) else
               f.algorithm.lower())
        out[f.asset] = {fam}
    return out
