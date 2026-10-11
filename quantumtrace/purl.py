"""Package URLs (purl, https://github.com/package-url/purl-spec) for declared libraries.

    ("pypi", "cryptography", "46.0.5")                 -> pkg:pypi/cryptography@46.0.5
    ("maven", "org.bouncycastle:bcprov-jdk18on", "1.80") -> pkg:maven/org.bouncycastle/bcprov-jdk18on@1.80
    ("npm", "@noble/post-quantum", "0.5.0")            -> pkg:npm/%40noble/post-quantum@0.5.0
    ("golang", "stdlib", "1.24")                       -> pkg:golang/stdlib@1.24

CycloneDX components carry a purl, so the CBOM (Phase 3) can use these directly.
"""
from __future__ import annotations

import re


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    path = name.replace(":", "/") if ecosystem == "maven" else name
    path = path.replace("@", "%40")
    return f"pkg:{ecosystem}/{path}" + (f"@{version}" if version else "")


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """'pkg:maven/org.bouncycastle/bcprov-jdk18on@1.80' -> ('maven', 'org.bouncycastle:bcprov-jdk18on', '1.80')."""
    body = purl.removeprefix("pkg:")
    eco, _, rest = body.partition("/")
    name, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    name = name.replace("%40", "@")
    if eco == "maven":
        name = name.replace("/", ":", 1)
    return eco, name, version or None


def version_tuple(v: str | None) -> tuple[int, ...]:
    """'v0.31.0' -> (0, 31, 0); '48.0.0rc1' -> (48, 0, 0); '1.24' -> (1, 24). Missing parts count as 0."""
    if not v:
        return ()
    nums = []
    for part in re.sub(r"^[^\d]*", "", v).split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums)


def version_at_least(v: str, minimum: str) -> bool:
    a, b = version_tuple(v), version_tuple(minimum)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) >= b + (0,) * (n - len(b))
