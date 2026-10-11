"""Loads catalog.yaml once and answers "which algorithm is this name?".

Name matching is forgiving on purpose: "SHA-256", "sha256", "SHA_256" and
"sha2-256" all normalise to the same key, so every input format (JCA strings,
AWS KeySpecs, OpenSSH names, IANA TLS names) can share one alias list.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

CATALOG_PATH = Path(__file__).with_name("catalog.yaml")


def norm(name: str) -> str:
    """'ECC_NIST_P256' -> 'eccnistp256'; 'aes256-gcm@openssh.com' -> 'aes256gcm'."""
    name = re.sub(r"@[\w.-]+$", "", name.strip().lower())
    return re.sub(r"[^a-z0-9+]", "", name)


@dataclass(frozen=True)
class AliasHit:
    key: str                  # catalog entry key, e.g. "AES"
    bits: int | None = None   # fixed by the alias or captured by a pattern
    mode: str | None = None


class Catalog:
    def __init__(self, data: dict):
        self.algorithms: dict[str, dict] = data["algorithms"]
        self.replacements: dict[str, dict] = data["replacements"]
        self.composites: dict[str, list] = {k.lower(): v for k, v in data.get("composites", {}).items()}
        self.composite_patterns = [(re.compile(p["regex"]), p["components"])
                                   for p in data.get("composite_patterns", [])]
        self.tls_cipher_suites: dict[int, str] = data.get("tls_cipher_suites", {})
        self.tls_groups: dict[int, str] = data.get("tls_groups", {})
        self.tls_signature_schemes: dict[int, str] = data.get("tls_signature_schemes", {})
        self.aws_elb_policies: dict[str, dict] = data.get("aws_elb_policies", {})
        self.x509_oids: dict[str, str] = {str(k): v for k, v in data.get("x509_oids", {}).items()}
        self.libraries: dict[str, dict] = {k.lower(): (v or {}) for k, v in data.get("libraries", {}).items()}

        self._aliases: dict[str, AliasHit] = {}
        self._patterns: list[tuple[re.Pattern, str]] = []
        for key, entry in self.algorithms.items():
            for alias in [key, *entry.get("aliases", [])]:
                if isinstance(alias, dict):
                    hit = AliasHit(key, alias.get("bits"), alias.get("mode"))
                    alias = alias["name"]
                else:
                    hit = AliasHit(key)
                n = norm(str(alias))
                other = self._aliases.get(n)
                if other is not None and other.key != key:
                    raise ValueError(f"alias {alias!r} used by both {other.key} and {key}")
                self._aliases.setdefault(n, hit)
            for pat in entry.get("patterns", []):
                self._patterns.append((re.compile(pat), key))

    # ------------------------------------------------------------------ lookups
    def resolve(self, name: str) -> AliasHit | None:
        """Single algorithm name -> catalog entry (+ bits/mode if the name says so)."""
        hit = self._aliases.get(norm(name))
        if hit:
            return hit
        low = re.sub(r"@[\w.-]+$", "", name.strip().lower())
        for regex, key in self._patterns:
            m = regex.match(low)
            if m:
                groups = m.groupdict()
                bits = int(groups["bits"]) if groups.get("bits") else None
                return AliasHit(key, bits, groups.get("mode"))
        return None

    def entry(self, key: str) -> dict:
        return self.algorithms[key]

    def library(self, ecosystem: str, name: str) -> tuple[str, dict] | None:
        """('pypi', 'Cryptography') -> ('pypi:cryptography', entry). Exact key first, then '*' patterns."""
        key = f"{ecosystem}:{name}".lower()
        if key in self.libraries:
            return key, self.libraries[key]
        for k, entry in self.libraries.items():
            if "*" in k and fnmatch.fnmatchcase(key, k):
                return k, entry
        return None

    @staticmethod
    def _code(code: int | str) -> int:
        return int(code, 16) if isinstance(code, str) else int(code)

    def tls_suite_name(self, code: int | str) -> str | None:
        return self.tls_cipher_suites.get(self._code(code))

    def tls_group_name(self, code: int | str) -> str | None:
        return self.tls_groups.get(self._code(code))

    def tls_sigscheme_name(self, code: int | str) -> str | None:
        return self.tls_signature_schemes.get(self._code(code))


@lru_cache(maxsize=1)
def load_catalog(path: str | Path = CATALOG_PATH) -> Catalog:
    with open(path, encoding="utf-8") as fh:
        return Catalog(yaml.safe_load(fh))
