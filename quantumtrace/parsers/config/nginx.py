"""nginx configs: `server {}` blocks -> TLS servers (and plain-HTTP servers).

    http {                                  <- ssl_* here are inherited by every server
        ssl_protocols TLSv1.2 TLSv1.3;
        server {
            listen 443 ssl;                 <- `ssl` on the listen = this port speaks TLS
            server_name api.example.lab;    <- asset "api.example.lab:443"
            ssl_ciphers HIGH:!aNULL:!MD5;
            ssl_ecdh_curve X25519MLKEM768:X25519;
            ssl_certificate /etc/nginx/certs/api.pem;
        }
    }

Defaults (nginx.org docs): ssl_protocols TLSv1.2 TLSv1.3 (since 1.23.4), ssl_ciphers
HIGH:!aNULL:!MD5, ssl_ecdh_curve auto, and no ssl_dhparam -> DHE suites are not used.
`include` is followed when the included file was scanned too.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .tls import Directive, TlsServer, min_protocol_name

TLS_DIRECTIVES = {"ssl_protocols", "ssl_ciphers", "ssl_ecdh_curve", "ssl_certificate", "ssl_dhparam", "ssl"}
CONTEXTS = {"http", "stream", "mail"}


@dataclass
class Node:
    name: str
    args: list[str]
    line: int
    children: list["Node"] | None = None
    file: str = ""

    def text(self) -> str:
        return f"{self.name} {' '.join(self.args)};".replace(" ;", ";")


# ====================================================================== tokenizer + parser
def tokenize(text: str):
    """Yield (token, line). Tokens are words, '{', '}' and ';'. Handles quotes and # comments."""
    i, line, n = 0, 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
        elif ch.isspace():
            i += 1
        elif ch == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif ch in "{};":
            yield ch, line
            i += 1
        elif ch in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != ch:
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            yield "".join(buf), line
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};":
                j += 1
            yield text[i:j], line
            i = j


def parse(text: str, file: str = "") -> list[Node]:
    root: list[Node] = []
    stack = [root]
    words: list[tuple[str, int]] = []
    for tok, line in tokenize(text):
        if tok == ";":
            if words:
                stack[-1].append(Node(words[0][0], [w for w, _ in words[1:]], words[0][1], None, file))
            words = []
        elif tok == "{":
            if words:
                node = Node(words[0][0], [w for w, _ in words[1:]], words[0][1], [], file)
                stack[-1].append(node)
                stack.append(node.children)
            words = []
        elif tok == "}":
            if len(stack) > 1:
                stack.pop()
            words = []
        else:
            words.append((tok, line))
    return root


def splice_includes(nodes: list[Node], files: dict[str, list[Node]], consumed: set[str], depth: int = 0) -> list[Node]:
    """Replace `include pattern;` by the nodes of the scanned files it matches."""
    out = []
    for nd in nodes:
        if nd.name == "include" and nd.children is None and nd.args and depth < 5:
            for rel in match_include(nd.args[0], files):
                consumed.add(rel)
                out += splice_includes(files[rel], files, consumed, depth + 1)
            continue
        if nd.children is not None:
            nd = Node(nd.name, nd.args, nd.line, splice_includes(nd.children, files, consumed, depth), nd.file)
        out.append(nd)
    return out


def match_include(pattern: str, files: dict) -> list[str]:
    """'/etc/nginx/sites-enabled/*' matches a scanned 'deploy/nginx/sites-enabled/api.conf'
    (compare the last 2 path components with glob rules)."""
    pat = PurePosixPath(pattern).parts[-2:]
    out = []
    for rel in sorted(files):
        parts = PurePosixPath(rel).parts[-len(pat):]
        if len(parts) == len(pat) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(parts, pat)):
            out.append(rel)
    return out


# ====================================================================== servers
@dataclass
class Listen:
    port: str
    ssl: bool
    line: int
    text: str


@dataclass
class NginxServer:
    file: str
    line: int
    names: list[str]
    listens: list[Listen]
    settings: dict[str, Node] = field(default_factory=dict)      # effective ssl_* directives
    conf_commands: list[Node] = field(default_factory=list)
    redirect: bool = False
    context: str = "http"


def servers(nodes: list[Node], file: str) -> list[NginxServer]:
    out: list[NginxServer] = []

    def visit(nodes, inherited: dict, inherited_cmds: list, context: str):
        level = dict(inherited)
        own_cmds = [n for n in nodes if n.name == "ssl_conf_command" and n.children is None]
        cmds = own_cmds or inherited_cmds              # nginx: inherited only if none on this level
        for n in nodes:
            if n.children is None and n.name in TLS_DIRECTIVES:
                level[n.name] = n
        certs = [n for n in nodes if n.name == "ssl_certificate" and n.children is None]
        if certs:
            level["_certs"] = certs
        for n in nodes:
            if n.children is None:
                continue
            if n.name in CONTEXTS:
                visit(n.children, level, cmds, n.name)
            elif n.name == "server":
                out.append(_server(n, level, cmds, context, file))

    visit(nodes, {}, [], "http")
    return out


def _server(node: Node, inherited: dict, inherited_cmds: list, context: str, file: str) -> NginxServer:
    settings = {k: v for k, v in inherited.items()}
    own = node.children or []
    for n in own:
        if n.children is None and n.name in TLS_DIRECTIVES:
            settings[n.name] = n
    certs = [n for n in own if n.name == "ssl_certificate" and n.children is None]
    if certs:
        settings["_certs"] = certs
    own_cmds = [n for n in own if n.name == "ssl_conf_command" and n.children is None]
    ssl_on = "ssl" in settings and settings["ssl"].args[:1] == ["on"]

    listens = []
    for n in own:
        if n.name == "listen" and n.children is None and n.args:
            port = _port(n.args[0])
            if port:
                listens.append(Listen(port, ssl_on or any(a in ("ssl", "quic") for a in n.args[1:]), n.line, n.text()))
    if not listens and context == "http":
        listens.append(Listen("443" if ssl_on else "80", ssl_on, node.line, "(no listen directive: *:80)"))
    names = next((n.args for n in own if n.name == "server_name" and n.children is None), [])
    return NginxServer(file=node.file or file, line=node.line, names=[x for x in names if x not in ("_", '""', "")],
                       listens=listens, settings=settings, conf_commands=own_cmds or inherited_cmds,
                       redirect=_redirects_to_https(own), context=context)


def _port(addr: str) -> str | None:
    if addr.startswith("unix:"):
        return None
    if addr.isdigit():
        return addr
    m = re.search(r":(\d+)$", addr)
    return m.group(1) if m else "80"


def _redirects_to_https(nodes: list[Node]) -> bool:
    for n in nodes:
        if n.name == "return" and any(a.startswith("https://") for a in n.args):
            return True
        if n.name == "rewrite" and len(n.args) >= 2 and n.args[1].startswith("https://"):
            return True
        if n.children and _redirects_to_https(n.children):
            return True
    return False


def to_tls_servers(s: NginxServer, rel: str) -> tuple[list[TlsServer], list[tuple[Listen, str]]]:
    """-> TLS servers (one per TLS port) and plaintext listeners (listen, asset)."""
    host = s.names[0] if s.names else f"{rel}:{s.line}"
    tls, plain = [], []
    seen = set()

    def d(key: str) -> Directive | None:
        n = s.settings.get(key)
        return Directive(" ".join(n.args), n.line, n.text(), n.file) if n else None

    for lis in s.listens:
        asset = f"{host}:{lis.port}"
        if asset in seen:
            continue
        seen.add(asset)
        if not lis.ssl:
            if s.context == "http":
                plain.append((lis, asset))
            continue
        srv = TlsServer(software="nginx", rel=rel, line=s.line, asset=asset, protocols=d("ssl_protocols"),
                        ciphers=d("ssl_ciphers"), groups=d("ssl_ecdh_curve"), dhparam=d("ssl_dhparam"),
                        certificates=[Directive(n.args[0], n.line, n.text(), n.file) for n in s.settings.get("_certs", [])
                                      if n.args],
                        default_protocols=("1.2", "1.3"), default_ciphers="HIGH:!aNULL:!MD5", dhe_needs_dhparam=True)
        if srv.groups and srv.groups.value.strip().lower() == "auto":
            srv.groups = None
        for c in s.conf_commands:                      # ssl_conf_command Ciphersuites / Groups / MinProtocol
            if len(c.args) < 2:
                continue
            key, val = c.args[0].lower(), " ".join(c.args[1:])
            if key == "ciphersuites":
                srv.ciphersuites = Directive(val, c.line, c.text(), c.file)
            elif key in ("groups", "curves"):
                srv.groups = Directive(val, c.line, c.text(), c.file)
            elif key == "minprotocol":
                srv.min_protocol = min_protocol_name(val)
        tls.append(srv)
    return tls, plain
