"""Apache httpd configs: `<VirtualHost>` sections -> TLS servers (and plain-HTTP servers).

    SSLProtocol all -SSLv3                         <- main-server settings are inherited by vhosts
    <VirtualHost *:443>
        ServerName shop.example.lab                <- asset "shop.example.lab:443"
        SSLEngine on                               <- this vhost speaks TLS
        SSLCipherSuite HIGH:!aNULL:!MD5            <- TLS <= 1.2 suites
        SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384
        SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519
        SSLCertificateFile /etc/ssl/shop.pem
    </VirtualHost>

Defaults (httpd.apache.org mod_ssl docs): SSLEngine off, SSLCipherSuite DEFAULT (depends on
the OpenSSL version). When SSLProtocol is not set we assume TLS 1.2 + 1.3 and say so.
`Include` / `IncludeOptional` are followed when the included file was scanned too.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from .nginx import match_include
from .tls import Directive, TlsServer, min_protocol_name

SECTION_OPEN = re.compile(r"^<\s*([\w.]+)\s*([^>]*)>$")
SECTION_CLOSE = re.compile(r"^</\s*([\w.]+)\s*>$")
IGNORED_SECTIONS = {"directory", "directorymatch", "location", "locationmatch", "files", "filesmatch", "if",
                    "elseif", "else", "limit", "limitexcept", "proxy", "proxymatch"}
TLS_KEYS = {"sslengine", "sslprotocol", "sslciphersuite", "sslopensslconfcmd", "sslcertificatefile", "servername"}


@dataclass
class Line:
    name: str                 # lower-case directive name
    args: list[str]
    line: int
    text: str
    file: str = ""


@dataclass
class VHost:
    file: str
    line: int
    addresses: list[str]
    lines: list[Line] = field(default_factory=list)


def logical_lines(text: str, file: str) -> list[tuple[int, str]]:
    out, buf, start = [], "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not buf:
            start = i
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        s = (buf + s).strip()
        buf = ""
        if s and not s.startswith("#"):
            out.append((start, s))
    return out


def _split(s: str) -> list[str]:
    try:
        return shlex.split(s, comments=False, posix=True)
    except ValueError:
        return s.split()


def parse(text: str, file: str, files: dict[str, str], consumed: set[str], depth: int = 0
          ) -> tuple[list[Line], list[VHost]]:
    """-> (main-server directives, virtual hosts). Includes of scanned files are inlined."""
    main: list[Line] = []
    vhosts: list[VHost] = []
    stack: list[str] = []
    current: VHost | None = None
    for line, s in logical_lines(text, file):
        m = SECTION_OPEN.match(s)
        if m and not s.startswith("</"):
            name = m.group(1).lower()
            stack.append(name)
            if name == "virtualhost":
                current = VHost(file, line, _split(m.group(2)))
                vhosts.append(current)
            continue
        m = SECTION_CLOSE.match(s)
        if m:
            name = m.group(1).lower()
            if stack:
                stack.pop()
            if name == "virtualhost":
                current = None
            continue
        if any(sec in IGNORED_SECTIONS for sec in stack):
            continue                                   # per-directory settings: not the handshake
        words = _split(s)
        if not words:
            continue
        d = Line(words[0].lower(), words[1:], line, s, file)
        if d.name in ("include", "includeoptional") and d.args and depth < 5:
            for rel in match_include(d.args[0], files):
                consumed.add(rel)
                m2, v2 = parse(files[rel], rel, files, consumed, depth + 1)
                (current.lines if current else main).extend(m2)
                vhosts += v2
            continue
        (current.lines if current else main).append(d)
    return main, vhosts


def _redirects_to_https(lines: list[Line]) -> bool:
    for d in lines:
        if d.name in ("redirect", "redirectmatch", "redirectpermanent", "rewriterule") and \
                any(a.startswith("https://") for a in d.args):
            return True
    return False


def _port(addr: str, listens: list[str]) -> str:
    m = re.search(r":(\d+)$", addr)
    if m:
        return m.group(1)
    return listens[0] if listens else "80"


def to_tls_servers(main: list[Line], vhosts: list[VHost], rel: str):
    """-> (TLS servers, plaintext listeners [(line, asset, port, redirect, evidence)])."""
    listens = [re.search(r"(\d+)$", d.args[0]).group(1) for d in main
               if d.name == "listen" and d.args and re.search(r"(\d+)$", d.args[0])]
    global_name = next((d.args[0] for d in main if d.name == "servername" and d.args), None)
    tls, plain = [], []
    hosts = vhosts or ([VHost(rel, 1, [f"*:{p}" for p in (listens or ['80'])])] if any(
        d.name == "sslengine" for d in main) else [])
    for vh in hosts:
        lines = [d for d in main if d.name in TLS_KEYS] + vh.lines          # vhost overrides main server
        eff: dict[str, Line] = {}
        for d in lines:
            if d.name not in ("sslciphersuite", "sslopensslconfcmd", "sslcertificatefile"):
                eff[d.name] = d
        name = (eff["servername"].args[0] if "servername" in eff and eff["servername"].args
                else global_name or f"{vh.file}:{vh.line}")
        engine = "sslengine" in eff and eff["sslengine"].args[:1] and eff["sslengine"].args[0].lower() == "on"
        for addr in vh.addresses or ["*"]:
            port = _port(addr, listens)
            asset = f"{name}:{port}"
            if not engine:
                plain.append((vh.line, asset, port, _redirects_to_https(vh.lines), f"<VirtualHost {addr}>"))
                continue
            srv = TlsServer(software="apache", rel=vh.file if vh.file else rel, line=vh.line, asset=asset,
                            default_protocols=("1.2", "1.3"), default_ciphers="DEFAULT", dhe_needs_dhparam=False)
            if "sslprotocol" in eff:
                d = eff["sslprotocol"]
                srv.protocols = Directive(" ".join(d.args), d.line, d.text, d.file)
            vh_certs = [d for d in vh.lines if d.name == "sslcertificatefile" and d.args]
            certs = vh_certs or [d for d in main if d.name == "sslcertificatefile" and d.args]
            srv.certificates = [Directive(d.args[0], d.line, d.text, d.file) for d in certs]
            for d in lines:                            # later lines (vhost) win
                if d.name == "sslciphersuite" and d.args:
                    if len(d.args) >= 2 and d.args[0].upper() == "TLSV1.3":
                        srv.ciphersuites = Directive(" ".join(d.args[1:]), d.line, d.text, d.file)
                    elif len(d.args) >= 2 and d.args[0].upper() == "SSL":
                        srv.ciphers = Directive(" ".join(d.args[1:]), d.line, d.text, d.file)
                    else:
                        srv.ciphers = Directive(" ".join(d.args), d.line, d.text, d.file)
                elif d.name == "sslopensslconfcmd" and len(d.args) >= 2:
                    key, val = d.args[0].lower(), " ".join(d.args[1:])
                    if key in ("groups", "curves", "ecdhparameters"):
                        srv.groups = Directive(val, d.line, d.text, d.file)
                    elif key == "ciphersuites":
                        srv.ciphersuites = Directive(val, d.line, d.text, d.file)
                    elif key == "minprotocol":
                        srv.min_protocol = min_protocol_name(val)
            tls.append(srv)
    return tls, plain
