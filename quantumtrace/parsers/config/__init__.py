"""Server configuration files (Phase 2d): nginx, Apache httpd, OpenSSH.

Files are recognised by name first (nginx.conf, httpd.conf, sshd_config, ...) and
otherwise by content ("server {", "<VirtualHost", "KexAlgorithms ..."), because real
configs often have no extension (sites-enabled/api) or a generic one (.conf).
"""
from __future__ import annotations

import re
from pathlib import Path

from ...catalog import Catalog, load_catalog
from ...models import Finding
from . import apache, nginx
from .ssh import parse_ssh_config
from .tls import plaintext_finding, resolve_path, tls_server_findings

CANDIDATE_SUFFIXES = {".conf", ".cfg", ".config", ".vhost", ".nginx", ".site", ""}
NAMES = {"nginx.conf": "nginx", "httpd.conf": "apache", "apache2.conf": "apache", "ssl.conf": "apache",
         "httpd-ssl.conf": "apache", "sshd_config": "ssh", "ssh_config": "ssh"}
MAX_BYTES = 2 * 1024 * 1024
_APACHE = re.compile(r"(?im)^\s*(<VirtualHost\b|SSL(Engine|Protocol|CipherSuite|CertificateFile)\s)")
_NGINX_BLOCK = re.compile(r"(?m)^\s*(server|http|stream|events|location\s+\S+)\s*\{")
_NGINX_DIRECTIVE = re.compile(r"(?m)(?:^|[{;])\s*(listen|server_name|ssl_\w+|proxy_pass|root|include|return)\s+[^;{}\n]*;")
_SSH = re.compile(r"(?im)^\s*(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|PubkeyAcceptedAlgorithms|HostKey)"
                  r"\s*(?:=\s*|\s+)[+^-]?[\w@./+-]+(?:,[\w@./+-]+)*\s*$")


def detect(path: Path) -> str | None:
    """'nginx' | 'apache' | 'ssh' | None."""
    name = path.name.lower()
    if name in NAMES:
        return NAMES[name]
    parent = path.parent.name.lower()
    if (name == "config" and parent == ".ssh") or parent in ("sshd_config.d", "ssh_config.d"):
        return "ssh"
    if path.suffix.lower() not in CANDIDATE_SUFFIXES and parent not in ("sites-enabled", "sites-available", "conf.d"):
        return None
    text = _read(path)
    if text is None:
        return None
    if _APACHE.search(text):
        return "apache"
    directives = len(_NGINX_DIRECTIVE.findall(text))
    if directives >= 2 or (directives and _NGINX_BLOCK.search(text)):
        return "nginx"                                 # a lone "server {" in prose is not enough
    ssh_keys = {m.group(1).lower() for m in _SSH.finditer(text)}
    if ssh_keys and ("ssh" in str(path).lower() or len(ssh_keys) >= 2):
        return "ssh"
    return None


def _read(path: Path) -> str | None:
    try:
        raw = Path(path).read_bytes()[:MAX_BYTES]
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None                                    # binary
    return raw.decode("utf-8", "replace")


def parse_config_files(paths: list[Path], root: Path | None = None, catalog: Catalog | None = None,
                       cert_families: dict[str, set[str]] | None = None,
                       known_files: list[str] | None = None) -> list[Finding]:
    """`cert_families`: certificate file -> key families (from the certificate parser), so TLS
    suites the server's certificate can't use are dropped. `known_files`: every scanned file,
    to resolve paths named in the configs (ssl_certificate, HostKey)."""
    cat = catalog or load_catalog()
    cert_families = cert_families or {}
    known = known_files or []
    texts: dict[str, tuple[str, str]] = {}
    for p in paths:
        kind, text = detect(Path(p)), _read(Path(p))
        if kind and text is not None:
            rel = str(Path(p).relative_to(root)) if root else Path(p).name
            texts[rel] = (kind, text)

    out: list[Finding] = []
    # nginx: parse all, inline includes, then report every file not included by another
    ng = {rel: nginx.parse(t, rel) for rel, (k, t) in texts.items() if k == "nginx"}
    consumed: set[str] = set()
    spliced = {rel: nginx.splice_includes(nodes, ng, consumed) for rel, nodes in ng.items()}
    for rel in sorted(ng):
        if rel in consumed:
            continue
        for s in nginx.servers(spliced[rel], rel):
            tls, plain = nginx.to_tls_servers(s, s.file or rel)
            out += _tls(tls, cat, cert_families, known)
            for lis, asset in plain:
                out.append(plaintext_finding("nginx", s.file or rel, lis.line, asset, lis.port, s.redirect, lis.text))

    ap_texts = {rel: t for rel, (k, t) in texts.items() if k == "apache"}
    consumed = set()
    parsed = {rel: apache.parse(t, rel, ap_texts, consumed) for rel, t in ap_texts.items()}
    for rel in sorted(parsed):
        if rel in consumed:
            continue
        main, vhosts = parsed[rel]
        tls, plain = apache.to_tls_servers(main, vhosts, rel)
        out += _tls(tls, cat, cert_families, known)
        for line, asset, port, redirect, ev in plain:
            out.append(plaintext_finding("apache", rel, line, asset, port, redirect, ev))

    for rel, (kind, text) in sorted(texts.items()):
        if kind == "ssh":
            out += parse_ssh_config(text, rel, cat, lambda v, r=rel: resolve_path(v, r, known))
    return out


def _tls(servers, cat, cert_families, known) -> list[Finding]:
    out = []
    for srv in servers:
        out += tls_server_findings(srv, cat, cert_families, lambda v, r=srv.rel: resolve_path(v, r, known))
    return out
