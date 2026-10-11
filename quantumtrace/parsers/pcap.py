"""PCAP parser (Phase 2c): network traffic via tshark.

    tshark (one pass, fields only)  ->  frames  ->  sessions (one per TCP stream)  ->  Findings

Per session it reports what was NEGOTIATED (decision 6):
  TLS  ServerHello cipher suite, key-exchange group (key_share or ServerKeyExchange
       curve), the signature scheme of the ServerKeyExchange, and for TLS <= 1.2 the
       certificate chain (key type/size, signature algorithm, expiry). TLS 1.3
       certificates are encrypted -> flagged `certificate-not-observable`.
       Works for TLS on any port tshark recognises, incl. SMTP STARTTLS and Postgres SSLRequest.
  SSH  both KEXINITs -> the algorithm the RFC 4253 rule picks (first client entry the
       server also supports); weaker algorithms both sides still allow -> `downgrade-risk`.
  Plaintext application protocols (HTTP, FTP, SMTP without STARTTLS, ...) -> `plaintext`.
What clients OFFER (groups, signature schemes) is aggregated into stats, not findings.

The file is fed to tshark on stdin, so it also works where AppArmor stops tshark opening files.
"""
from __future__ import annotations

import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from ..catalog import Catalog, load_catalog
from ..classify import classify_name
from ..models import Finding, Tier, Usage

EXTENSIONS = {".pcap", ".pcapng", ".cap"}
AGG = ";"                     # tshark aggregator between repeated occurrences of a field
EXPIRING_SOON = timedelta(days=30)

FIELDS = [
    "frame.number", "frame.protocols", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack",
    # TLS
    "tls.handshake.type", "tls.handshake.version", "tls.handshake.extensions.supported_version",
    "tls.handshake.ciphersuite", "tls.handshake.extensions_supported_group",
    "tls.handshake.extensions_key_share_group", "tls.handshake.sig_hash_alg",
    "tls.handshake.extensions_server_name", "tls.handshake.server_named_curve",
    # certificates (visible in TLS <= 1.2)
    "tls.handshake.certificate",                          # raw DER bytes -> decoded with `cryptography`
    "x509af.algorithm.id", "pkcs1.modulus", "pkcs1.namedCurve", "x509af.utcTime", "x509af.generalizedTime",
    # SSH
    "ssh.protocol", "ssh.message_code", "ssh.kex_algorithms", "ssh.server_host_key_algorithms",
    "ssh.encryption_algorithms_client_to_server", "ssh.encryption_algorithms_server_to_client",
    "ssh.mac_algorithms_client_to_server", "ssh.mac_algorithms_server_to_client",
    # cleartext protocols / upgrades
    "smtp.req.command", "pgsql.type", "http.host", "http.request.method", "http.response.code",
    "http.location", "ftp.request.command", "imap.request", "pop.request.command",
]
DISPLAY_FILTER = ("tls.handshake or ssh or http or smtp or pgsql or ftp or telnet or pop or imap or ldap "
                  "or mysql or tds or (tcp.flags.syn==1 and tcp.flags.ack==0)")
PLAINTEXT_PROTOCOLS = {"http", "ftp", "telnet", "smtp", "pop", "imap", "ldap", "pgsql", "mysql", "tds"}
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}
SSH_PSEUDO = ("ext-info-", "kex-strict-")          # markers in the kex list, not algorithms
SSH_AEAD = ("chacha20-poly1305", "aes128-gcm", "aes256-gcm")


class TsharkError(RuntimeError):
    pass


# =================================================================== tshark
def find_tshark() -> str | None:
    return shutil.which("tshark")


@lru_cache(maxsize=1)
def available_fields(tshark: str) -> frozenset[str]:
    """Field names this tshark version knows (names change between versions; asking for an
    unknown field makes tshark refuse to run)."""
    out = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True, check=False).stdout
    return frozenset(line.split("\t")[2] for line in out.splitlines() if line.startswith("F\t"))


def run_tshark(path: Path, tshark: str) -> list[dict[str, str]]:
    known = available_fields(tshark)
    fields = [f for f in FIELDS if f in known] if known else FIELDS
    cmd = [tshark, "-r", "-", "-n", "-Y", DISPLAY_FILTER, "-T", "fields", "-E", "header=n",
           "-E", f"aggregator={AGG}", "-E", "occurrence=a"]
    for f in fields:
        cmd += ["-e", f]
    with open(path, "rb") as fh:                     # stdin: works even where AppArmor blocks `-r file`
        proc = subprocess.run(cmd, stdin=fh, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TsharkError(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "tshark failed")
    return [dict(zip(fields, line.split("\t"))) for line in proc.stdout.splitlines()]


# =================================================================== sessions
@dataclass
class Session:
    stream: int
    first_frame: int = 0
    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    protocols: set[str] = field(default_factory=set)
    sni: str = ""
    # TLS
    client_hello: dict = field(default_factory=dict)
    server_hello: dict = field(default_factory=dict)
    certificate_frame: dict = field(default_factory=dict)
    starttls: str = ""                                # "smtp" / "postgres" / ...
    # SSH
    ssh_banners: dict = field(default_factory=dict)   # "client"/"server" -> banner
    ssh_kexinit: dict = field(default_factory=dict)   # "client"/"server" -> field dict
    # cleartext
    http_host: str = ""
    http_redirect_https: bool = False

    @property
    def kind(self) -> str:
        if self.server_hello or self.client_hello:
            return "tls"
        if self.ssh_kexinit or self.ssh_banners:
            return "ssh"
        if self.protocols & PLAINTEXT_PROTOCOLS:
            return "plaintext"
        return "other"

    def endpoint_name(self) -> str:
        host = self.sni or self.http_host or (self.server[0] if self.server else "?")
        return f"{host}:{self.server[1] if self.server else '?'}"


def _vals(row: dict, key: str) -> list[str]:
    v = row.get(key, "")
    return [x for x in v.split(AGG) if x] if v else []


def _first(row: dict, key: str) -> str:
    vals = _vals(row, key)
    return vals[0] if vals else ""


def _true(v: str) -> bool:
    return v in ("1", "True", "true")


def build_sessions(rows: list[dict]) -> dict[int, Session]:
    sessions: dict[int, Session] = {}
    for row in rows:
        if not row.get("tcp.stream"):
            continue
        sid = int(row["tcp.stream"])
        s = sessions.setdefault(sid, Session(stream=sid, first_frame=int(row.get("frame.number") or 0)))
        src = (row.get("ip.src") or row.get("ipv6.src") or "?", int(row.get("tcp.srcport") or 0))
        dst = (row.get("ip.dst") or row.get("ipv6.dst") or "?", int(row.get("tcp.dstport") or 0))
        s.protocols |= set(row.get("frame.protocols", "").split(":"))

        if _true(row.get("tcp.flags.syn", "")) and not _true(row.get("tcp.flags.ack", "")):
            s.client, s.server = src, dst                       # SYN goes client -> server

        types = _vals(row, "tls.handshake.type")
        if "1" in types:
            s.client_hello = row
            s.client, s.server = s.client or src, s.server or dst
            s.sni = s.sni or _first(row, "tls.handshake.extensions_server_name")
        if "2" in types:
            s.server_hello = row
            s.server, s.client = s.server or src, s.client or dst
        if "11" in types:
            s.certificate_frame = row

        if "smtp" in s.protocols and any(c.upper().startswith("STAR") for c in _vals(row, "smtp.req.command")):
            s.starttls = "smtp"
        if "SSL request" in row.get("pgsql.type", ""):
            s.starttls = "postgres"
        if "imap" in s.protocols and "STARTTLS" in row.get("imap.request", "").upper():
            s.starttls = "imap"

        banner = _first(row, "ssh.protocol")
        if banner:
            side = "server" if s.server and src == s.server else "client"
            s.ssh_banners[side] = banner
        if "20" in _vals(row, "ssh.message_code"):              # SSH_MSG_KEXINIT
            side = "server" if (s.server and src == s.server) or (not s.server and src[1] == 22) else "client"
            s.ssh_kexinit[side] = row

        if row.get("http.host"):
            s.http_host = s.http_host or row["http.host"]
        if row.get("http.location", "").lower().startswith("https://"):
            s.http_redirect_https = True
    return sessions


# =================================================================== findings
def _hex(v: str) -> int | None:
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None


def _f(s: Session, rel: str, frame: dict | None, **kw) -> Finding:
    fr = (frame or {}).get("frame.number") or s.first_frame
    return Finding(source="pcap", location=f"{rel}:stream {s.stream}, frame {fr}", asset=s.endpoint_name(),
                   related=[f"{s.client[0]}:{s.client[1]}"] if s.client else [], library="network", **kw)


def tls_findings(s: Session, rel: str, cat: Catalog, now: datetime) -> list[Finding]:
    sh, ch = s.server_hello, s.client_hello
    if not sh:                                       # ClientHello only: the server never answered
        return [_f(s, rel, ch, algorithm="tls-handshake-incomplete", usage=Usage.PROTOCOL,
                   evidence="ClientHello without ServerHello", context="TLS handshake not completed",
                   flags={"incomplete-handshake"}, confidence=0.3, details={"protocol": "tls"})]
    sv = _hex(_first(sh, "tls.handshake.extensions.supported_version")) or _hex(_first(sh, "tls.handshake.version"))
    version = TLS_VERSIONS.get(sv or 0, f"0x{sv or 0:04x}")
    flags: set[str] = set()
    legacy = {"SSL 3.0": "ssl3-negotiated", "1.0": "tls1.0-negotiated", "1.1": "tls1.1-negotiated"}
    if version in legacy:
        flags.add(legacy[version])
    if s.starttls:
        flags.add(f"starttls-{s.starttls}")
    upgrade = {"smtp": " after SMTP STARTTLS", "postgres": " after Postgres SSLRequest",
               "imap": " after IMAP STARTTLS"}.get(s.starttls, "")
    ctx = f"TLS {version} negotiated{upgrade}"
    out = []

    # 1. cipher suite
    code = _hex(_first(sh, "tls.handshake.ciphersuite"))
    suite = cat.tls_suite_name(code) if code is not None else None
    suite_flags = set(flags) | ({"certificate-not-observable"} if version == "1.3" else set())
    tls = {"protocol": "tls", "tls_version": version}
    out.append(_f(s, rel, sh, algorithm=suite or f"TLS cipher suite 0x{code or 0:04X}", usage=Usage.PROTOCOL,
                  evidence=f"ServerHello cipher_suite=0x{code or 0:04X}", context=ctx, flags=suite_flags,
                  details={**tls, **({"suite_id": f"0x{code:04X}"} if code is not None else {})}))

    # 2. key-exchange group: TLS 1.3 key_share, TLS 1.2 ServerKeyExchange named curve
    gcode = _hex(_first(sh, "tls.handshake.extensions_key_share_group")) or \
        _hex(_first(sh, "tls.handshake.server_named_curve"))
    if gcode is not None:
        group = cat.tls_group_name(gcode) or f"TLS group 0x{gcode:04X}"
        gflags = set(flags)
        offered = [_hex(x) for x in _vals(ch, "tls.handshake.extensions_supported_group")] if ch else []
        offered_pq = [cat.tls_group_name(x) for x in offered if x is not None and cat.tls_group_name(x)
                      and classify_name(cat.tls_group_name(x), catalog=cat).tier is Tier.SAFE]
        if offered_pq and classify_name(group, catalog=cat).tier is not Tier.SAFE:
            gflags.add("client-offered-pq")          # clients are ready; only the server needs changing
        out.append(_f(s, rel, sh, algorithm=group, usage=Usage.KEY_EXCHANGE, flags=gflags, context=ctx,
                      details={**tls, "group_id": f"0x{gcode:04X}"},
                      evidence=f"ServerHello key_share/named_curve=0x{gcode:04X}"
                               + (f" (client offered: {', '.join(cat.tls_group_name(x) or hex(x) for x in offered if x is not None)})" if offered else "")))

    # 3. signature scheme used in the ServerKeyExchange (TLS 1.2; encrypted in 1.3)
    if version != "1.3":
        scode = _hex(_first(sh, "tls.handshake.sig_hash_alg"))
        if scode is not None:
            out.append(_f(s, rel, sh, algorithm=cat.tls_sigscheme_name(scode) or f"TLS signature scheme 0x{scode:04X}",
                          usage=Usage.SIGNATURE, flags=set(flags), context=ctx,
                          details={**tls, "sigscheme_id": f"0x{scode:04X}"},
                          evidence=f"ServerKeyExchange signature_algorithm=0x{scode:04X}"))

    # 4. certificate chain (only visible before TLS 1.3)
    cf = s.certificate_frame
    if cf and version != "1.3":
        out += _certificate_findings(s, rel, cf, cat, now, flags, ctx)
    elif version != "1.3":
        out[0].flags.add("certificate-not-captured")      # should be visible, but is not in this capture
    return out


def _certificate_findings(s, rel, cf, cat, now, flags, ctx) -> list[Finding]:
    """Certificates: decode the raw DER bytes ourselves (independent of the tshark version);
    fall back to tshark's X.509 dissector fields if the raw bytes are not available."""
    ders = _vals(cf, "tls.handshake.certificate")
    if ders:
        found = _certificate_findings_der(s, rel, cf, cat, now, flags, ctx, ders)
        if found:
            return found
    return _certificate_findings_fields(s, rel, cf, cat, now, flags, ctx)


def _cert_flags(flags: set, i: int, not_after, now) -> set:
    cflags = set(flags) | ({"certificate-chain"} if i else set())
    if not_after and not_after < now:
        cflags.add("expired")
    elif not_after and not_after < now + EXPIRING_SOON:
        cflags.add("expiring-soon")
    return cflags


def _certificate_findings_der(s, rel, cf, cat, now, flags, ctx, ders) -> list[Finding]:
    from cryptography import x509

    from .x509util import certificate_facts

    out = []
    for i, h in enumerate(ders):
        try:
            cert = x509.load_der_x509_certificate(bytes.fromhex(h.replace(":", "")))
        except ValueError:
            continue
        facts = certificate_facts(cert, cat, now)
        cflags = set(flags) | facts.flags | ({"certificate-chain"} if i else set())
        cctx = f"{ctx}; certificate {i} of chain ({facts.subject}), valid until {facts.not_after:%Y-%m-%d}"
        out.append(_f(s, rel, cf, algorithm=facts.key_name, usage=Usage.CERTIFICATE, key_size=facts.key_bits,
                      flags=set(cflags), context=cctx, evidence=f"certificate[{i}] public key {facts.key_oid or '?'}",
                      details=facts.details("public-key")))
        out.append(_f(s, rel, cf, algorithm=facts.sig_name, usage=Usage.CERTIFICATE, flags=set(cflags),
                      context=cctx, evidence=f"certificate[{i}] signatureAlgorithm {facts.sig_oid}",
                      details=facts.details("signature")))
    return out


def _certificate_findings_fields(s, rel, cf, cat, now, flags, ctx) -> list[Finding]:
    """Fallback. x509af.algorithm.id repeats per certificate as: [tbs signature, public key, signature]."""
    oids = _vals(cf, "x509af.algorithm.id")
    moduli = _vals(cf, "pkcs1.modulus")
    curves = _vals(cf, "pkcs1.namedCurve")
    times = _vals(cf, "x509af.utcTime") + _vals(cf, "x509af.generalizedTime")
    out = []
    for i in range(len(oids) // 3):
        sig_oid, key_oid = oids[3 * i], oids[3 * i + 1]
        not_after = _parse_time(times[2 * i + 1]) if len(times) > 2 * i + 1 else None
        cflags = _cert_flags(flags, i, not_after, now)
        cctx = f"{ctx}; certificate {i} of chain" + (f", valid until {not_after:%Y-%m-%d}" if not_after else "")

        key_name = cat.x509_oids.get(key_oid, f"OID {key_oid}")
        bits = None
        if key_name == "RSA" and moduli:
            modulus = moduli.pop(0).replace(":", "")
            if modulus.startswith("00"):                   # DER adds a 0x00 sign byte
                modulus = modulus[2:]
            bits = len(modulus) * 4
        elif key_name == "ECDSA" and curves:
            key_name = cat.x509_oids.get(curves.pop(0), key_name)
        cdet = {"cert": f"{rel}:stream {s.stream}:certificate {i}"}
        if not_after:
            cdet["not_after"] = not_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        out.append(_f(s, rel, cf, algorithm=key_name, usage=Usage.CERTIFICATE, key_size=bits, flags=set(cflags),
                      context=cctx, evidence=f"certificate[{i}] subjectPublicKeyInfo {key_oid}",
                      details={**cdet, "cert_part": "public-key"}))
        out.append(_f(s, rel, cf, algorithm=cat.x509_oids.get(sig_oid, f"OID {sig_oid}"), usage=Usage.CERTIFICATE,
                      flags=set(cflags), context=cctx, evidence=f"certificate[{i}] signatureAlgorithm {sig_oid}",
                      details={**cdet, "cert_part": "signature"}))
    return out


def _parse_time(v: str) -> datetime | None:
    v = v.replace(" (UTC)", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def ssh_findings(s: Session, rel: str, cat: Catalog) -> list[Finding]:
    c, sv = s.ssh_kexinit.get("client"), s.ssh_kexinit.get("server")
    banners = ", ".join(f"{k} {v}" for k, v in sorted(s.ssh_banners.items()))
    ctx = f"SSH ({banners})" if banners else "SSH"
    if not (c or sv):
        return [_f(s, rel, None, algorithm="ssh-kexinit-missing", usage=Usage.PROTOCOL, context=ctx,
                   details={"protocol": "ssh"},
                   evidence="SSH banner without KEXINIT", flags={"incomplete-handshake"}, confidence=0.3)]
    out = []
    lists = [("ssh.kex_algorithms", Usage.KEY_EXCHANGE, "kex"),
             ("ssh.server_host_key_algorithms", Usage.SIGNATURE, "host key"),
             ("ssh.encryption_algorithms_client_to_server", Usage.ENCRYPTION, "cipher"),
             ("ssh.mac_algorithms_client_to_server", Usage.MAC, "mac")]
    chosen_cipher = ""
    for key, usage, label in lists:
        cl = _names(c, key) if c else []
        sl = _names(sv, key) if sv else []
        if c and sv:
            chosen = next((a for a in cl if a in sl), None)       # RFC 4253 7.1: first client choice the server supports
            confidence, extra = 1.0, set()
        else:
            chosen = (cl or sl or [None])[0]                    # only one side seen: best guess
            confidence, extra = 0.7, {"negotiation-inferred"}
        if chosen is None:
            continue
        if label == "cipher":
            chosen_cipher = chosen
        if label == "mac" and chosen_cipher.split("@")[0].startswith(SSH_AEAD):
            continue                                            # AEAD cipher: the MAC list is not used
        frame = sv or c
        out.append(_f(s, rel, frame, algorithm=chosen, usage=usage, flags=extra, confidence=confidence,
                      details={"protocol": "ssh", "ssh_role": label},
                      context=f"{ctx}; negotiated {label}", evidence=f"KEXINIT {label}: {chosen}"))

        # downgrade risk: weaker algorithms BOTH sides still accept
        both = [a for a in cl if a in sl and a != chosen] if c and sv else []
        chosen_cls = classify_name(chosen, catalog=cat)
        for alt in both:
            alt_cls = classify_name(alt, catalog=cat)
            weaker = alt_cls.tier.severity > chosen_cls.tier.severity or \
                bool((alt_cls.flags - chosen_cls.flags) & {"classically-broken", "weak-key-size", "deprecated"})
            if weaker:
                out.append(_f(s, rel, frame, algorithm=alt, usage=usage, flags={"offered", "downgrade-risk"},
                              details={"protocol": "ssh", "ssh_role": label},
                              confidence=0.6, context=f"{ctx}; {label} also accepted by both sides",
                              evidence=f"KEXINIT {label} lists (client+server) include {alt}"))
    return out


def _names(row: dict, key: str) -> list[str]:
    raw = row.get(key, "").split(AGG)[0]
    return [a for a in raw.split(",") if a and not a.startswith(SSH_PSEUDO)]


def plaintext_findings(s: Session, rel: str) -> list[Finding]:
    proto = next((p for p in ("http", "ftp", "telnet", "smtp", "pop", "imap", "ldap", "pgsql", "mysql", "tds")
                  if p in s.protocols), "tcp")
    flags = {"redirect-to-https"} if s.http_redirect_https else set()
    return [_f(s, rel, None, algorithm="plaintext", usage=Usage.PROTOCOL, flags=flags,
               context=f"{proto.upper()} without TLS" + (" (redirects to HTTPS)" if flags else ""),
               evidence=f"{proto.upper()} traffic in clear text", details={"protocol": proto})]


# =================================================================== entry point
@dataclass
class PcapStats:
    files: int = 0
    sessions: Counter = field(default_factory=Counter)          # tls / ssh / plaintext / other
    tls_versions: Counter = field(default_factory=Counter)
    negotiated_groups: Counter = field(default_factory=Counter)
    offered_groups: Counter = field(default_factory=Counter)     # what clients support (ClientHello)
    offered_sig_schemes: Counter = field(default_factory=Counter)
    pq_sessions: int = 0                                        # TLS sessions with a SAFE (PQ/hybrid) group

    @property
    def pqc_readiness(self) -> float | None:
        tls = self.sessions.get("tls", 0)
        return self.pq_sessions / tls if tls else None

    def to_dict(self) -> dict:
        return {"files": self.files, "sessions": dict(self.sessions), "tls_versions": dict(self.tls_versions),
                "negotiated_groups": dict(self.negotiated_groups), "offered_groups": dict(self.offered_groups),
                "offered_signature_schemes": dict(self.offered_sig_schemes), "pq_sessions": self.pq_sessions,
                "pqc_readiness": self.pqc_readiness}


def parse_pcap_files(paths: list[Path], root: Path | None = None, now: datetime | None = None,
                     catalog: Catalog | None = None) -> tuple[list[Finding], PcapStats, list[str]]:
    cat = catalog or load_catalog()
    now = now or datetime.now(timezone.utc)
    stats, warnings, out = PcapStats(), [], []
    tshark = find_tshark()
    if not tshark:
        return [], stats, ["tshark not found: install Wireshark/tshark to scan PCAP files "
                           f"({len(paths)} file(s) skipped)"]
    for p in paths:
        rel = str(Path(p).relative_to(root)) if root else Path(p).name
        try:
            rows = run_tshark(Path(p), tshark)
        except (TsharkError, OSError) as e:
            warnings.append(f"{rel}: {e}")
            continue
        stats.files += 1
        for s in sorted(build_sessions(rows).values(), key=lambda s: s.stream):
            kind = s.kind
            stats.sessions[kind] += 1
            if kind == "tls":
                found = tls_findings(s, rel, cat, now)
                _tls_stats(stats, s, found, cat)
            elif kind == "ssh":
                found = ssh_findings(s, rel, cat)
            elif kind == "plaintext":
                found = plaintext_findings(s, rel)
            else:
                found = []
            out += found
    return out, stats, warnings


def _tls_stats(stats: PcapStats, s: Session, found: list[Finding], cat: Catalog) -> None:
    for f in found:
        if f.usage is Usage.KEY_EXCHANGE:
            stats.negotiated_groups[f.algorithm] += 1
            if classify_name(f.algorithm, catalog=cat).tier is Tier.SAFE:
                stats.pq_sessions += 1
        if f.usage is Usage.PROTOCOL and f.context.startswith("TLS "):
            stats.tls_versions[f.context.split()[1]] += 1
    ch = s.client_hello
    if ch:
        for g in _vals(ch, "tls.handshake.extensions_supported_group"):
            code = _hex(g)
            stats.offered_groups[cat.tls_group_name(code) or g] += 1
        for sig in _vals(ch, "tls.handshake.sig_hash_alg"):
            code = _hex(sig)
            stats.offered_sig_schemes[cat.tls_sigscheme_name(code) or sig] += 1
