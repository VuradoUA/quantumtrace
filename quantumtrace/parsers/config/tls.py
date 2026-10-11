"""What a TLS server config ALLOWS (nginx `server {}`, Apache `<VirtualHost>`), as Findings.

A config file does not show a handshake, it shows what the server will accept. So, like
the AWS ELB policies in Phase 2a, every finding is flagged `offered`:

  * one finding per TLS <= 1.2 cipher suite the cipher string enables
  * one finding per TLS 1.3 cipher suite
  * one finding per key-exchange group (or one `ECDHE` finding when groups are left
    to the OpenSSL default); classical groups next to a post-quantum one -> `downgrade-risk`
  * enabled legacy protocols become flags on the suites: ssl3-enabled, tls1.0-enabled, ...

OpenSSL cipher strings ("HIGH:!aNULL:!MD5", "EECDH+AESGCM") are expanded with the OpenSSL
library Python itself links against (`ssl` module), i.e. the same expansion `openssl ciphers`
would give on this machine. Explicit names that this OpenSSL no longer ships (RC4-SHA,
DES-CBC3-SHA, ...) are still reported: the config asks for them.
"""
from __future__ import annotations

import posixpath
import re
import ssl
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ...catalog import Catalog
from ...classify import _openssl_suite, classify_name
from ...models import Finding, Tier, Usage

PROTOCOL_FLAGS = {"SSLv2": "ssl2-enabled", "SSLv3": "ssl3-enabled", "1.0": "tls1.0-enabled", "1.1": "tls1.1-enabled"}
LEGACY_PROTOCOLS = {"SSLv2", "SSLv3", "1.0", "1.1", "1.2"}
TLS13_DEFAULT = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"]
PROTOCOL_NAMES = {"sslv2": "SSLv2", "sslv3": "SSLv3", "tlsv1": "1.0", "tlsv1.0": "1.0", "tlsv1.1": "1.1",
                  "tlsv1.2": "1.2", "tlsv1.3": "1.3"}
ORDER = ["SSLv2", "SSLv3", "1.0", "1.1", "1.2", "1.3"]


@dataclass
class Directive:
    value: str
    line: int
    text: str                         # the directive as written, for `evidence`
    file: str = ""                    # set when it comes from another (included / main) file


@dataclass
class TlsServer:
    software: str                     # nginx | apache
    rel: str                          # config file (relative to the scan root)
    line: int                         # where the server block starts
    asset: str                        # "host:port"
    protocols: Directive | None = None
    min_protocol: str | None = None   # from ssl_conf_command / SSLOpenSSLConfCmd MinProtocol
    ciphers: Directive | None = None          # TLS <= 1.2 cipher string
    ciphersuites: Directive | None = None     # TLS 1.3 suites
    groups: Directive | None = None
    certificates: list[Directive] = field(default_factory=list)
    dhparam: Directive | None = None
    default_protocols: tuple[str, ...] = ("1.2", "1.3")
    default_ciphers: str = "DEFAULT"
    dhe_needs_dhparam: bool = False   # nginx: no ssl_dhparam -> DHE suites are never used


@dataclass
class Suite:
    name: str                         # IANA name when known (TLS_ECDHE_RSA_WITH_...), else the OpenSSL name
    openssl: str
    kx: str                           # kx-ecdhe | kx-dhe | kx-rsa | ...
    auth: str                         # auth-rsa | auth-ecdsa | auth-dss | auth-null | ...
    explicit_only: bool = False       # named in the config but not available in the local OpenSSL build


# ====================================================================== protocols
def parse_protocols(value: str, base: set[str] | None = None) -> set[str]:
    """'TLSv1.2 TLSv1.3' (nginx) or 'all -SSLv3 -TLSv1' (Apache) -> {'1.2', '1.3'}."""
    out = set(base or ())
    for tok in value.replace(",", " ").split():
        sign, name = (tok[0], tok[1:]) if tok[0] in "+-" else ("+", tok)
        names = ORDER[1:] if name.lower() == "all" else [PROTOCOL_NAMES.get(name.lower())]   # "all": SSLv3 + TLS (no SSLv2)
        for n in names:
            if n is None:
                continue
            (out.add if sign == "+" else out.discard)(n)
    return out


def min_protocol_name(value: str) -> str | None:
    return PROTOCOL_NAMES.get(value.strip().lower())


# ====================================================================== cipher strings
_EXCLUDE_ALIASES = {"3DES": ("DES-CBC3",), "ENULL": ("NULL",), "NULL": ("NULL",), "ANULL": ("ADH-", "AECDH-"),
                    "ADH": ("ADH-",), "AECDH": ("AECDH-",), "EXPORT": ("EXP-",), "EXP": ("EXP-",),
                    "LOW": ("DES-CBC-", "EXP-"), "MEDIUM": ("RC4", "DES-CBC3"), "RC4": ("RC4",),
                    "DES": ("DES-CBC-",), "MD5": ("-MD5",), "SHA1": ("-SHA",), "SHA": ("-SHA",)}


def _excluded(name: str, negatives: list[str]) -> bool:
    up = name.upper()
    for neg in negatives:
        n = neg.upper()
        if n == up:
            return True
        for marker in _EXCLUDE_ALIASES.get(n, ()):
            if (marker.endswith("-") and up.startswith(marker)) or (marker.startswith("-") and up.endswith(marker)) \
                    or (marker[0] not in "-" and marker[-1] != "-" and marker in up):
                return True
        if n in ("KRSA", "RSA") and _kx_from_name(up) == "kx-rsa":
            return True
    return False


def _kx_from_name(up: str) -> str:
    up = up.upper().removeprefix("EXP-")
    if up.startswith(("ECDHE-", "AECDH-")):
        return "kx-ecdhe"
    if up.startswith(("DHE-", "EDH-", "ADH-")):
        return "kx-dhe"
    return "kx-rsa"


def _auth_from_name(up: str) -> str:
    up = up.upper()
    if up.startswith(("ADH-", "AECDH-")):
        return "auth-null"
    if "-ECDSA-" in up:
        return "auth-ecdsa"
    if "-DSS-" in up:
        return "auth-dss"
    return "auth-rsa"


_KX = {("kx-ecdhe", "auth-rsa"): "ECDHE_RSA", ("kx-ecdhe", "auth-ecdsa"): "ECDHE_ECDSA",
       ("kx-dhe", "auth-rsa"): "DHE_RSA", ("kx-dhe", "auth-dss"): "DHE_DSS", ("kx-rsa", "auth-rsa"): "RSA",
       ("kx-ecdhe", "auth-null"): "ECDH_anon", ("kx-dhe", "auth-null"): "DH_anon"}


def _iana_name(c: dict, cat: Catalog) -> str:
    """ssl.get_ciphers() entry -> IANA suite name (catalog first, else built from its fields)."""
    known = cat.tls_suite_name(c["id"] & 0xFFFF)
    if known:
        return known
    kx = _KX.get((c.get("kea"), c.get("auth")))
    sym = (c.get("symmetric") or "").lower()
    if not kx or not sym:
        return c["name"]
    if sym == "des-ede3-cbc":
        cipher = "3DES_EDE_CBC"
    elif sym == "rc4":
        cipher = "RC4_128"
    else:
        cipher = sym.upper().replace("-", "_")
        if cipher.endswith("_CCM") and c["name"].endswith("CCM8"):
            cipher += "_8"
    digest = (c.get("digest") or "").lower()
    if digest:
        mac = {"sha1": "SHA", "sha256": "SHA256", "sha384": "SHA384", "md5": "MD5"}.get(digest, digest.upper())
    elif "CCM" in cipher:
        mac = ""
    else:                                              # AEAD: the name carries the PRF hash
        mac = "SHA384" if c["name"].endswith("SHA384") else "SHA256"
    return f"TLS_{kx}_WITH_{cipher}" + (f"_{mac}" if mac else "")


def expand_cipher_string(spec: str, cat: Catalog) -> list[Suite]:
    """OpenSSL cipher string -> TLS <= 1.2 suites, in OpenSSL's order."""
    tokens = [t for t in re.split(r"[:,\s]+", spec.strip()) if t]
    suites: list[Suite] = []
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_ciphers(":".join(tokens) + ("" if "@SECLEVEL" in spec.upper() else ":@SECLEVEL=0"))
        for c in ctx.get_ciphers():
            if c.get("protocol") != "TLSv1.3":
                suites.append(Suite(_iana_name(c, cat), c["name"], c.get("kea") or "", c.get("auth") or ""))
    except ssl.SSLError:                               # nothing this OpenSSL knows (e.g. only "RC4-SHA")
        pass
    have = {s.openssl.upper() for s in suites}
    negatives = [t[1:] for t in tokens if t[0] in "!-"]
    for t in tokens:
        if t[0] in "!-+@" or t.upper() in have or _excluded(t, negatives):
            continue
        if t.upper().startswith("TLS_") or _openssl_suite(t.lower()):
            suites.append(Suite(t, t, _kx_from_name(t), _auth_from_name(t), explicit_only=True))
            have.add(t.upper())
    return suites


def parse_groups(value: str) -> tuple[list[str], bool]:
    """'X25519MLKEM768:X25519:prime256v1' / '?*X25519MLKEM768 / ?*X25519:?secp256r1' -> names, uses_default."""
    names, default = [], False
    for tok in re.split(r"[:,/\s]+", value):
        tok = tok.strip().lstrip("?*")
        if not tok or tok.startswith("-"):
            continue
        if tok.upper() in ("DEFAULT", "AUTO"):
            default = True
            continue
        if tok not in names:
            names.append(tok)
    return names, default


# ====================================================================== findings
def tls_server_findings(srv: TlsServer, cat: Catalog, cert_families: dict[str, set[str]],
                        resolve) -> list[Finding]:
    """`resolve(configured_path)` -> the scanned file it refers to (or None)."""
    protos = parse_protocols(srv.protocols.value) if srv.protocols else set(srv.default_protocols)
    if srv.min_protocol in ORDER:
        protos = {p for p in protos if ORDER.index(p) >= ORDER.index(srv.min_protocol)}
    base = {"offered"} | {PROTOCOL_FLAGS[p] for p in protos if p in PROTOCOL_FLAGS}
    proto_txt = ", ".join(("TLS " + p) if p[0].isdigit() else p for p in ORDER if p in protos) or "none"
    if srv.protocols is None:
        proto_txt += f" ({srv.software} default)"

    related, families = [], set()
    for d in srv.certificates:
        target = resolve(d.value)
        related.append(target or d.value)
        families |= cert_families.get(target or "", set())
    who = f"{srv.software} server {srv.asset} [{proto_txt}]"

    tls = {"protocol": "tls", "tls_versions": ",".join(p for p in ORDER if p in protos)}

    def mk(directive: Directive | None, **kw) -> Finding:
        line = directive.line if directive else srv.line
        file = (directive.file if directive else "") or srv.rel
        return Finding(source="config", location=f"{file}:{line}", asset=srv.asset, related=list(related),
                       library=srv.software, details=dict(tls), **kw)

    out: list[Finding] = []
    kex_needed = "1.3" in protos

    # ---- TLS <= 1.2 cipher suites
    if protos & LEGACY_PROTOCOLS:
        spec = srv.ciphers.value if srv.ciphers else srv.default_ciphers
        ev = srv.ciphers.text if srv.ciphers else f"(no cipher directive: {srv.software} default '{spec}')"
        notes = []
        suites = [s for s in expand_cipher_string(spec, cat) if "psk" not in s.kx and "srp" not in s.kx
                  and s.auth not in ("auth-psk", "auth-srp")]           # need PSK/SRP setup the config doesn't have
        if srv.dhe_needs_dhparam and srv.dhparam is None and any(s.kx == "kx-dhe" for s in suites):
            suites = [s for s in suites if s.kx != "kx-dhe"]
            notes.append("DHE suites unusable: no ssl_dhparam")
        if families:
            need = {"auth-rsa": "rsa", "auth-ecdsa": "ec", "auth-dss": "dsa"}
            kept = [s for s in suites if s.auth not in need or need[s.auth] in families]
            if len(kept) != len(suites):
                notes.append(f"suites for other certificate types dropped (certificate key: {', '.join(sorted(families))})")
            suites = kept
        note = f"; {'; '.join(notes)}" if notes else ""
        tokset = {t.upper() for t in re.split(r"[:,\s]+", spec) if t}
        for s in suites:
            flags = set(base)
            if srv.ciphers is None:
                flags.add("default-ciphers")
            if s.explicit_only:
                flags.add("not-in-local-openssl")
            explicit = s.openssl.upper() in tokset
            out.append(mk(srv.ciphers, algorithm=s.name, usage=Usage.PROTOCOL, flags=flags, evidence=ev,
                          confidence=1.0 if explicit else 0.9 if srv.ciphers else 0.8,
                          context=f"TLS <=1.2 cipher suite ({s.openssl}) enabled on {who}{note}"))
            kex_needed |= s.kx in ("kx-ecdhe", "kx-dhe")

    # ---- TLS 1.3 cipher suites
    if "1.3" in protos:
        names = [n for n in re.split(r"[:,\s]+", srv.ciphersuites.value) if n] if srv.ciphersuites else TLS13_DEFAULT
        ev = srv.ciphersuites.text if srv.ciphersuites else "(TLS 1.3 suites not configured: OpenSSL default)"
        for n in names:
            out.append(mk(srv.ciphersuites, algorithm=n, usage=Usage.PROTOCOL, evidence=ev,
                          flags=set(base) | ({"default-ciphers"} if srv.ciphersuites is None else set()),
                          context=f"TLS 1.3 cipher suite enabled on {who}"))

    # ---- key-exchange groups
    if kex_needed:
        names, uses_default = parse_groups(srv.groups.value) if srv.groups else ([], True)
        pq = [g for g in names if classify_name(g, catalog=cat).tier is Tier.SAFE]
        for g in names:
            flags = set(base)
            if pq and g not in pq:
                flags.add("downgrade-risk")          # classical fallback next to a post-quantum group
            out.append(mk(srv.groups, algorithm=g, usage=Usage.KEY_EXCHANGE, flags=flags, evidence=srv.groups.text,
                          context=f"key-exchange group {'(post-quantum hybrid) ' if g in pq else ''}allowed on {who}"))
        if uses_default:
            out.append(mk(srv.groups, algorithm="ECDHE", usage=Usage.KEY_EXCHANGE, confidence=0.6,
                          flags=set(base) | {"default-groups"} | ({"downgrade-risk"} if pq else set()),
                          evidence=srv.groups.text if srv.groups else "(no group directive: OpenSSL default list)",
                          context=f"key-exchange groups left to the OpenSSL default on {who}: classical (EC)DHE "
                                  "(OpenSSL >= 3.5 also offers X25519MLKEM768 by default)"))
    return out


def plaintext_finding(software: str, rel: str, line: int, asset: str, port: str, redirect: bool,
                      evidence: str) -> Finding:
    return Finding(source="config", location=f"{rel}:{line}", asset=asset, algorithm="plaintext",
                   usage=Usage.PROTOCOL, flags={"redirect-to-https"} if redirect else set(), evidence=evidence,
                   library=software, details={"protocol": "http"},
                   context=f"{software} server on port {port} without TLS" + (" (redirects to HTTPS)" if redirect else ""))


# ====================================================================== configured paths -> scanned files
def resolve_path(configured: str, config_rel: str, known: list[str]) -> str | None:
    """'/etc/nginx/certs/api.pem' in nginx/conf.d/site.conf -> 'nginx/certs/api.pem' if that file was scanned.
    Relative paths are tried relative to the config file first; otherwise the longest matching path suffix."""
    if not configured or "$" in configured:
        return None
    cfg = PurePosixPath(configured.replace("\\", "/"))
    if not cfg.is_absolute():
        cand = posixpath.normpath(str(PurePosixPath(config_rel).parent / cfg))
        if cand in known:
            return cand
    parts = cfg.parts
    best, best_len = None, 0
    for k in known:
        kp = PurePosixPath(k).parts
        if not kp or kp[-1] != parts[-1]:
            continue
        n = 0
        while n < min(len(kp), len(parts)) and kp[-1 - n] == parts[-1 - n]:
            n += 1
        if n > best_len:
            best, best_len = k, n
    return best
