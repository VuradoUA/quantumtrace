"""OpenSSH configs: sshd_config (server) and ssh_config / ~/.ssh/config (client).

    KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,diffie-hellman-group14-sha1
    Ciphers chacha20-poly1305@openssh.com,aes128-cbc
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha1
    HostKeyAlgorithms rsa-sha2-512,ssh-rsa
    HostKey /etc/ssh/ssh_host_rsa_key

Every listed algorithm is ALLOWED (flag `offered`); the peer picks one (RFC 4253 rule).
A value starting with '+' appends to OpenSSH's built-in default (flag
`appended-to-default`), '-' removes from it (nothing to report), '^' puts it first.
Classical key exchange next to a post-quantum one -> `downgrade-risk` (like TLS groups).
"""
from __future__ import annotations

import re

from ...catalog import Catalog
from ...classify import classify_name
from ...models import Finding, Tier, Usage

KEYWORDS = {
    "kexalgorithms": (Usage.KEY_EXCHANGE, "key exchange"),
    "ciphers": (Usage.ENCRYPTION, "cipher"),
    "macs": (Usage.MAC, "MAC"),
    "hostkeyalgorithms": (Usage.SIGNATURE, "host key algorithm"),
    "pubkeyacceptedalgorithms": (Usage.SIGNATURE, "accepted public key algorithm"),
    "pubkeyacceptedkeytypes": (Usage.SIGNATURE, "accepted public key algorithm"),
    "casignaturealgorithms": (Usage.SIGNATURE, "CA signature algorithm"),
    "hostbasedacceptedalgorithms": (Usage.SIGNATURE, "host-based auth algorithm"),
    "hostbasedacceptedkeytypes": (Usage.SIGNATURE, "host-based auth algorithm"),
}
SERVER_ONLY = {"hostkey", "permitrootlogin", "subsystem", "listenaddress", "authorizedkeysfile", "usepam",
               "passwordauthentication", "challengeresponseauthentication", "permitemptypasswords"}
HOST_KEY_TYPES = {"rsa": "RSA", "dsa": "DSA", "ecdsa": "ECDSA", "ed25519": "Ed25519", "ed448": "Ed448"}
LINE = re.compile(r"^\s*(\w+)\s*(?:=\s*|\s+)(.+?)\s*$")


def is_server(rel: str, text: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if "sshd" in name or "/sshd_config.d/" in f"/{rel}":
        return True
    if name == "ssh_config" or rel.endswith(".ssh/config") or "/ssh_config.d/" in f"/{rel}":
        return False
    words = {m.group(1).lower() for m in map(LINE.match, text.splitlines()) if m}
    return bool(words & SERVER_ONLY)


def parse_ssh_config(text: str, rel: str, cat: Catalog, resolve) -> list[Finding]:
    server = is_server(rel, text)
    role = "sshd" if server else "ssh client"
    block = ""                                         # "Host *.lab" / "Match User deploy"
    out: list[Finding] = []
    for i, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("#"):
            continue
        m = LINE.match(raw.split(" #")[0])
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip().strip('"')
        if key in ("host", "match"):
            block = f" [{m.group(1)} {value}]"
            continue
        asset = f"{rel}{block}"
        if key == "hostkey" and server:
            stem = value.rsplit("/", 1)[-1]
            kind = next((v for k, v in HOST_KEY_TYPES.items() if f"_{k}_" in f"_{stem}_" or stem.endswith(f"_{k}_key")),
                        None)
            target = resolve(value) or resolve(value + ".pub")
            out.append(Finding(source="config", location=f"{rel}:{i}", asset=asset, algorithm=kind or "unknown-host-key",
                               usage=Usage.SIGNATURE, flags={"host-key"}, evidence=raw.strip(), library="openssh",
                               details={"key": target or value, "key_type": "private-key"},
                               confidence=0.8 if kind else 0.3, related=[target or value],
                               context=f"{role} host key file {value} (type from the file name)"))
            continue
        if key not in KEYWORDS:
            continue
        usage, label = KEYWORDS[key]
        mode = value[0] if value[:1] in "+-^" else ""
        if mode == "-":
            continue                                   # removes algorithms from the default: nothing enabled
        algs = [a for a in value.lstrip("+-^").split(",") if a]
        pq = [a for a in algs if usage is Usage.KEY_EXCHANGE and classify_name(a, catalog=cat).tier is Tier.SAFE]
        for a in algs:
            flags = {"offered"}
            if mode == "+":
                flags.add("appended-to-default")
            if pq and a not in pq:
                flags.add("downgrade-risk")
            out.append(Finding(source="config", location=f"{rel}:{i}", asset=asset, algorithm=a, usage=usage,
                               flags=flags, evidence=raw.strip()[:160], library="openssh",
                               details={"protocol": "ssh", "ssh_role": label},
                               context=f"{role} {label} allowed by {m.group(1)}"
                                       + (" (appended to the OpenSSH default list)" if mode == "+" else "")))
    return out
