"""The Quantum Risk Classification Engine.

    finding.algorithm ("SHA1withRSA", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA_2048", ...)
        -> decompose into parts        (composite names have several algorithms)
        -> resolve each part           (catalog lookup: aliases, then regex patterns)
        -> build a ComponentResult     (tier, threat, role, flags, replacement, ...)
        -> aggregate                   (worst tier, HNDL, union of flags, replacements)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .catalog import Catalog, load_catalog
from .models import (CONFIDENTIALITY_ROLES, Classification, ComponentResult,
                     Finding, Tier, Usage)
from .purl import parse_purl, version_at_least

AE_MODES = {"gcm", "ccm", "ccm8", "ccm_8", "ocb"}      # authenticated-encryption modes
INSECURE_MODES = {"ecb"}


@dataclass
class Part:
    """One algorithm inside a (possibly composite) name, before resolution."""
    name: str
    role: Usage | None = None
    bits: int | None = None
    mode: str | None = None
    flags: set[str] = field(default_factory=set)


# ====================================================================== public API
def classify(finding: Finding, catalog: Catalog | None = None) -> Finding:
    """Fill finding.classification and return the same finding."""
    if finding.usage is Usage.LIBRARY:
        finding.classification = classify_library(finding, catalog or load_catalog())
        return finding
    finding.classification = classify_name(
        finding.algorithm, usage=finding.usage, key_size=finding.key_size,
        mode=finding.mode, flags=finding.flags, catalog=catalog)
    return finding


def classify_name(name: str, usage: Usage = Usage.UNKNOWN, key_size: int | None = None,
                  mode: str | None = None, flags: set[str] | frozenset = frozenset(),
                  catalog: Catalog | None = None) -> Classification:
    cat = catalog or load_catalog()
    usage = Usage(usage)
    parts = decompose(name, cat)
    if len(parts) == 1:                       # facts the parser knows apply to a single algorithm
        parts[0].bits = parts[0].bits or key_size
        parts[0].mode = parts[0].mode or mode
    components = [build_component(p, usage, flags, cat) for p in parts]
    return aggregate(components, flags)


# ====================================================================== 1. decompose
_TLS13 = re.compile(r"^tls_(aes_128_gcm|aes_256_gcm|chacha20_poly1305|aes_128_ccm_8|aes_128_ccm)_(sha256|sha384)$")
_TLS12 = re.compile(r"^tls_(?P<kx>.+?)_with_(?P<cipher>.+?)(?:_(?P<mac>sha|sha256|sha384|md5|null))?$")
_TLS_KX = {   # key-exchange part of a TLS 1.2 suite name -> (kex alg, auth alg, extra flags)
    "rsa": ("RSA", None, {"no-forward-secrecy"}),
    "ecdhe_rsa": ("ECDH", "RSA", set()),
    "ecdhe_ecdsa": ("ECDH", "ECDSA", set()),
    "dhe_rsa": ("DH", "RSA", set()),
    "dhe_dss": ("DH", "DSA", set()),
    "ecdh_rsa": ("ECDH", "RSA", {"no-forward-secrecy"}),
    "ecdh_ecdsa": ("ECDH", "ECDSA", {"no-forward-secrecy"}),
    "dh_anon": ("DH", None, {"anonymous"}),
    "ecdh_anon": ("ECDH", None, {"anonymous"}),
}
_WITH = re.compile(r"^(?P<a>[a-z0-9-]+?)_?with_?(?P<b>[a-z0-9-]+)$")


def decompose(name: str, cat: Catalog) -> list[Part]:
    low = re.sub(r"@[\w.-]+$", "", name.strip().lower())

    # a) known composite names (SSH, TLS signature schemes)
    if low in cat.composites:
        return _parts_from_specs(cat.composites[low], {})
    ssh = _ssh_key_variant(low)          # ssh-ed25519-cert-v01@openssh.com, sk-ssh-ed25519@openssh.com
    if ssh and ssh[0] in cat.composites:
        parts = _parts_from_specs(cat.composites[ssh[0]], {})
        for p in parts:
            p.flags |= ssh[1]
        return parts

    # b) regex families of composites (AWS KMS algorithm names, PBKDF2WithHmacX)
    for regex, specs in cat.composite_patterns:
        m = regex.match(low)
        if m:
            return _parts_from_specs(specs, m.groupdict())

    # c) TLS cipher suites
    m = _TLS13.match(low)
    if m:
        return [Part(m.group(1), Usage.ENCRYPTION), Part(m.group(2), Usage.HASH)]
    m = _TLS12.match(low)
    if m and m.group("kx") in _TLS_KX:
        kex, auth, extra = _TLS_KX[m.group("kx")]
        parts = [Part(kex, Usage.KEY_EXCHANGE, flags=set(extra))]
        if auth:
            parts.append(Part(auth, Usage.SIGNATURE))
        cipher = m.group("cipher")
        parts.append(Part("plaintext", Usage.ENCRYPTION, flags={"null-cipher"}) if cipher == "null"
                     else Part(cipher, Usage.ENCRYPTION))
        if m.group("mac") not in (None, "null"):
            parts.append(_suite_hash(m.group("mac"), cipher))
        return parts

    # c2) OpenSSL-style TLS 1.2 cipher names (AWS ELB policies, nginx, Apache)
    parts = _openssl_suite(low)
    if parts:
        return parts

    # d) JCA transformation "AES/ECB/PKCS5Padding"
    if "/" in low:
        alg, *rest = low.split("/")
        return [Part(alg, mode=rest[0] if rest else None)]

    # e) "SHA1withRSA", "SHA256WITHRSA", "ECDSA_WITH_SHA384"
    m = _WITH.match(low)
    if m and cat.resolve(m.group("a")) and cat.resolve(m.group("b")):
        return [Part(m.group("a")), Part(m.group("b"))]

    # f) a single algorithm
    return [Part(name.strip())]


_OSSL_CIPHER = r"(?P<cipher>aes(?:128|256)(?:-gcm|-ccm)?|chacha20-poly1305|des-cbc3|des-cbc|rc4|camellia(?:128|256)|null)"
_OSSL_MAC = r"(?P<mac>sha|sha256|sha384|md5)"
_OSSL_FS = re.compile(rf"^(?P<kx>ecdhe|dhe|edh)-(?P<au>rsa|ecdsa|dss|anon)-{_OSSL_CIPHER}(?:-{_OSSL_MAC})?$")
_OSSL_RSA = re.compile(rf"^{_OSSL_CIPHER}-{_OSSL_MAC}$")      # no prefix = static RSA key exchange


def _ssh_key_variant(low: str) -> tuple[str, set[str]] | None:
    """'ssh-ed25519-cert-v01' -> ('ssh-ed25519', {'ssh-certificate'}); 'sk-ssh-ed25519' -> (..., {'security-key'})."""
    base, flags = low, set()
    if re.search(r"-cert-v0[01]$", base):
        base, flags = re.sub(r"-cert-v0[01]$", "", base), flags | {"ssh-certificate"}
    if base.startswith("sk-"):
        base, flags = base[3:], flags | {"security-key"}
    return (base, flags) if flags else None


def _openssl_suite(low: str) -> list[Part] | None:
    """'ECDHE-RSA-AES128-GCM-SHA256' / 'AES128-SHA' / 'EXP-RC4-MD5' / 'ADH-AES256-SHA' -> parts (OpenSSL naming)."""
    extra = set()
    if low.startswith("exp-"):                         # 1990s export-grade (40/56-bit) suites
        low, extra = low[4:], {"export-grade", "classically-broken"}
    anon = re.match(r"^(adh|aecdh)-(.+)$", low)        # anonymous (EC)DH: no server authentication
    if anon:
        low = f"{'dhe' if anon.group(1) == 'adh' else 'ecdhe'}-anon-{anon.group(2)}"
    m = _OSSL_FS.match(low) or _OSSL_RSA.match(low)
    if not m:
        return None
    g = m.groupdict()
    if g.get("kx"):
        parts = [Part("ECDH" if g["kx"] == "ecdhe" else "DH", Usage.KEY_EXCHANGE, flags=set(extra))]
        if g["au"] == "anon":
            parts[0].flags.add("anonymous")
        else:
            parts.append(Part({"rsa": "RSA", "ecdsa": "ECDSA", "dss": "DSA"}[g["au"]], Usage.SIGNATURE))
    else:
        parts = [Part("RSA", Usage.KEY_EXCHANGE, flags={"no-forward-secrecy"} | extra)]
    c = g["cipher"]
    if c == "null":
        return parts + [Part("plaintext", Usage.ENCRYPTION, flags={"null-cipher"})] + \
            ([_suite_hash(g["mac"], c)] if g.get("mac") else [])
    cipher = {"des-cbc3": "3des-cbc", "des-cbc": "des-cbc", "rc4": "rc4"}.get(c)
    if cipher is None and c.startswith(("aes", "camellia")):
        mode = "gcm" if c.endswith("-gcm") else "ccm" if c.endswith("-ccm") else "cbc"
        cipher = f"{c.split('-')[0]}-{mode}"                   # aes128-cbc, aes256-gcm
    parts.append(Part(cipher or c, Usage.ENCRYPTION))
    if g.get("mac"):
        parts.append(_suite_hash(g["mac"], c))
    return parts


def _suite_hash(mac: str, cipher: str) -> Part:
    """The hash at the end of a TLS 1.2 suite name. With an AEAD cipher (GCM / CCM / ChaCha20-Poly1305)
    it is only the PRF hash; with CBC / RC4 / NULL it is the record MAC, i.e. HMAC-<hash>.
    This matters: HMAC-SHA1 is NOT broken by SHA-1 collisions, a SHA-1 signature is."""
    h = {"sha": "sha1"}.get(mac, mac)
    if re.search(r"gcm|ccm|chacha20|poly1305", cipher):
        return Part(h, Usage.HASH, flags={"prf-hash"})
    return Part(f"hmac-{h}", Usage.MAC)


def _parts_from_specs(specs: list[dict], groups: dict) -> list[Part]:
    parts = []
    for spec in specs:
        if spec.get("optional") and not groups.get(spec["optional"]):
            continue                                  # e.g. GCP RSA_SIGN_RAW_PKCS1_2048 has no hash
        bits = spec.get("bits")
        if isinstance(bits, str):
            bits = int(bits.format(**groups))
        parts.append(Part(spec["alg"].format(**groups),
                          Usage(spec["role"]) if spec.get("role") else None, bits, spec.get("mode")))
    return parts


# ====================================================================== 2+3. resolve + build
def build_component(part: Part, usage: Usage, finding_flags, cat: Catalog) -> ComponentResult:
    hit = cat.resolve(part.name)
    if hit is None:
        return ComponentResult(id=_slug(part.name), name=part.name, catalog_key=None, kind="unknown",
                               role=part.role or usage, tier=Tier.UNKNOWN, threat="unknown",
                               primitive="unknown", flags={"unrecognised"} | part.flags)

    e = cat.entry(hit.key)
    kind = e["kind"]
    bits = part.bits or hit.bits or e.get("bits")
    mode = (part.mode or hit.mode or "").lower() or None
    if kind == "asymmetric":
        mode = None                                   # "RSA/ECB/..." : ECB means nothing for RSA
    role = part.role or usage
    if role is Usage.UNKNOWN:                         # infer from the algorithm itself
        role = {"hash": Usage.HASH, "mac": Usage.MAC, "kdf": Usage.KDF,
                "symmetric": Usage.ENCRYPTION}.get(kind, role)
        if e.get("primitive") == "signature":
            role = Usage.SIGNATURE
        elif e.get("primitive") in ("key-agree", "kem"):
            role = Usage.KEY_EXCHANGE

    flags = set(e.get("flags", [])) | part.flags

    # ---- tier
    if "tier" in e:
        tier = Tier(e["tier"])
    elif bits is None:
        tier, flags = Tier.UNKNOWN, flags | {"key-size-unknown"}
    else:
        table = {int(k): v for k, v in e["tier_by_bits"].items()}
        tier = Tier(table.get(bits, "SAFE" if bits >= 256 else "MEDIUM"))

    if kind == "asymmetric" and bits and e.get("min_bits") and bits < e["min_bits"]:
        flags |= {"weak-key-size", "classically-broken"}
    if mode in INSECURE_MODES:
        flags.add("insecure-mode")

    # ---- primitive (CycloneDX vocabulary)
    primitive = e.get("primitive_by_role", {}).get(role.value, e.get("primitive", "unknown"))
    if kind == "symmetric" and mode in AE_MODES:
        primitive = "ae"

    # ---- security levels
    classical = _by_bits(e.get("classical_by_bits"), bits) or e.get("classical_level")
    nist = e.get("nist_level")
    if nist is None and bits is not None:
        nist = _by_bits(e.get("nist_level_by_bits"), bits)

    # ---- replacement + standard
    replacement, standard = e.get("replacement"), e.get("standard")
    if e["threat"] == "shor":
        if role in CONFIDENTIALITY_ROLES:
            r = cat.replacements["confidentiality"]
        elif "long-lived" in finding_flags:
            r = cat.replacements["long-lived-signature"]
        elif role in (Usage.SIGNATURE, Usage.CERTIFICATE):
            r = cat.replacements["signature"]
        else:
            r = None
        if r:
            replacement, standard = r["name"], r["standard"]
        else:
            k, s = cat.replacements["confidentiality"], cat.replacements["signature"]
            replacement = f"{k['name']} if used for key exchange/encryption, {s['name']} if used for signatures"
            standard = f"{k['standard']} / {s['standard']}"
    if tier is Tier.SAFE and kind not in ("pqc", "hybrid"):
        replacement = None                            # nothing to migrate

    # ---- display name + id
    name = e["name"]
    variable_size = "tier_by_bits" in e or "min_bits" in e or (kind == "asymmetric" and "bits" not in e)
    if bits and variable_size:
        name = f"{name}-{bits}"
    if mode:
        name = f"{name}-{mode.upper()}"

    return ComponentResult(
        id=_slug(name), name=name, catalog_key=hit.key, kind=kind, role=role, tier=tier,
        threat=e["threat"], primitive=primitive, bits=bits, mode=mode, oid=e.get("oid"),
        nist_quantum_level=nist, classical_level=classical, replacement=replacement,
        standard=standard, flags=flags)


def _by_bits(table: dict | None, bits: int | None):
    """Exact match, else the value for the largest key size <= bits."""
    if not table or bits is None:
        return None
    table = {int(k): v for k, v in table.items()}
    if bits in table:
        return table[bits]
    smaller = [k for k in table if k <= bits]
    return table[max(smaller)] if smaller else None


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


# ====================================================================== 4. aggregate
def aggregate(components: list[ComponentResult], finding_flags) -> Classification:
    tier = max((c.tier for c in components), key=lambda t: t.severity)
    flags = set(finding_flags)
    for c in components:
        flags |= c.flags
    if tier is Tier.PLAINTEXT and "redirect-to-https" in flags:
        tier = Tier.INFO                              # plain HTTP that only redirects to HTTPS
    # HNDL = recorded now, decrypted LATER. A NULL cipher (TLS_RSA_WITH_NULL_*) is readable now:
    # PLAINTEXT says that; the RSA key exchange then protects no data, so it is not HNDL.
    hndl = any(c.hndl for c in components) and not any(c.tier is Tier.PLAINTEXT for c in components)
    replacements: list[str] = []
    for c in components:
        if c.tier in (Tier.CRITICAL, Tier.MEDIUM, Tier.PLAINTEXT) and c.replacement:
            text = f"{c.name} -> {c.replacement} ({c.standard})"
            if text not in replacements:
                replacements.append(text)
    return Classification(tier=tier, hndl=hndl, components=components, flags=flags,
                          replacements=replacements)


# ====================================================================== libraries (inventory)
def classify_library(finding: Finding, cat: Catalog) -> Classification:
    """A crypto library declared in a manifest: always tier INFO (inventory, not scored).
    Flags say whether the DECLARED version can already do post-quantum crypto."""
    eco, name, _ = parse_purl(finding.purl) if finding.purl else ("", finding.algorithm, None)
    flags = set(finding.flags) | {"crypto-library"}
    replacements: list[str] = []
    hit = cat.library(eco, name)
    key, e = hit if hit else (None, {})
    display = e.get("display", name)
    ranged = "version-range" in flags
    lower = re.search(r"\d+(?:\.\d+)*", finding.version or "")
    version = lower.group() if lower and (not ranged or re.match(r"^(>=|~=|\^|~|>)", finding.version)) else None

    if e.get("deprecated"):
        flags.add("deprecated-library")
        replacements.append(f"{display}: {e['deprecated']}")
    if e.get("pqc") == "native":
        flags.add("pqc-library")
    elif e.get("pqc_since"):
        since, api = str(e["pqc_since"]), e.get("pqc_api", "ML-KEM / ML-DSA")
        if version and version_at_least(version, since):
            flags.add("pqc-capable")                 # the API is there (a range's lower bound counts); the code still has to use it
        elif version and not ranged:
            flags.add("no-pqc-api")
            replacements.append(f"{display} {version} -> upgrade to >= {since} for {api}")
        else:
            flags.add("pqc-not-guaranteed")          # unpinned / range that allows older versions
            replacements.append(f"{display} {finding.version or '(unpinned)'} -> require >= {since} for {api}")
        if e.get("verified") is False:
            flags.add("pqc-data-unverified")
    pq_tls = e.get("pq_tls_default_since")
    if pq_tls and version and version_at_least(version, str(pq_tls)):
        flags.add("pq-tls-default")
    if hit is None:
        flags.add("unrecognised")

    label = f"{display} {finding.version}" if finding.version else display
    comp = ComponentResult(id=_slug(f"lib-{name}-{version or 'any'}"), name=label, catalog_key=key,
                           kind="library", role=Usage.LIBRARY, tier=Tier.INFO, threat="none",
                           primitive="other", flags=set(flags))
    return Classification(tier=Tier.INFO, hndl=False, components=[comp], flags=flags,
                          replacements=replacements)
