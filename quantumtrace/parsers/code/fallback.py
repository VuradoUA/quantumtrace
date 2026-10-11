"""Regex fallback for languages without a tree-sitter grammar here (JS/TS, C/C++, C#,
Kotlin, Rust, Ruby, PHP, ...): decision 7.

It is deliberately conservative: it only reports
  * string literals that ARE an algorithm name the catalog knows
    ('md5', "aes-128-ecb", "SHA1withRSA", "RSA/ECB/OAEPPadding" ...)
  * a few well-known C/OpenSSL identifiers (EVP_aes_128_ecb, RSA_generate_key ...)
Findings get confidence 0.4 and the flag `regex-fallback`.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...catalog import Catalog
from ...classify import classify_name
from ...models import Finding, Usage

EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs",
              ".kt", ".kts", ".scala", ".rs", ".rb", ".php", ".swift", ".m"}
STRING = re.compile(r"""(?P<q>["'])(?P<s>[A-Za-z0-9_./+-]{3,48})(?P=q)""")
EVP = re.compile(r"\bEVP_(?P<s>(?:aes|des|rc4|chacha20|sha\d*|md5|camellia)[a-z0-9_]*)\s*\(")
C_CALLS = {re.compile(r"\bRSA_generate_key(?:_ex)?\s*\("): "RSA",
           re.compile(r"\bDSA_generate_key\s*\("): "DSA",
           re.compile(r"\bDH_generate_key\s*\("): "DH",
           re.compile(r"\bEC_KEY_new_by_curve_name\s*\(\s*NID_(?P<s>\w+)"): None}
# names that are words or too generic to trust on their own in a string
STOP = {"none", "null", "http", "https", "plaintext", "cleartext", "unencrypted", "sha", "ec", "dss", "dh",
        "dhe", "des", "hmac"}
LINE_COMMENT = re.compile(r"(^|\s)(//|#)(?!include).*$")
MODULUS = re.compile(r"\bmodulusLength\s*:\s*(\d{3,5})\b")      # Node / WebCrypto RSA key size


ANY_STRING = re.compile(r"""(["'`])(?:\\.|(?!\1).)*\1""")
# a list of algorithm names is crypto only when it IS a crypto setting: {algorithms: ['RS256']},
# ciphers = [...]; a list like REMOVED_ALGORITHMS = ['md5', 'sha1'] on a changelog page is not.
CRYPTO_LIST_KEY = re.compile(r"(?<![\w$])(?:algs?|algorithms?|ciphers?|ciphersuites|curves?|ecdhcurve|hash(?:es)?|"
                             r"digests?|sigalgs|groups)[\"']?\s*[:=]\s*$", re.I)


def _strings_in_use(line: str, stack: list[str]) -> list[str]:
    """Algorithm-name string literals on this line, skipping those that are elements of a list that
    is not a crypto setting. `stack` carries the open brackets over to the next line."""
    names, pos = [], 0
    for m in [*ANY_STRING.finditer(line), None]:
        code = line[pos:m.start() if m else len(line)]
        for j, ch in enumerate(code):
            if ch in "({":
                stack.append(ch)
            elif ch == "[":
                stack.append("[ok" if CRYPTO_LIST_KEY.search(line[:pos + j]) else "[no")
            elif ch in ")}]" and stack:
                stack.pop()
        if m is None:
            break
        pos = m.end()
        s = STRING.fullmatch(m.group(0))
        if s and not (stack and stack[-1] == "[no"):
            names.append(s.group("s"))
    return names


def parse_fallback(path: Path, rel: str, cat: Catalog) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    in_block = False
    stack: list[str] = []                              # open brackets across lines: "(", "{", "[ok", "[no"
    for i, raw in enumerate(lines, 1):
        line = raw
        if in_block:                                   # inside /* ... */
            if "*/" not in line:
                continue
            line, in_block = line.split("*/", 1)[1], False
        line = re.sub(r"/\*.*?\*/", "", line)
        if "/*" in line:
            line, in_block = line.split("/*", 1)[0], True
        line = LINE_COMMENT.sub("", line)

        if re.match(r"[A-Za-z_]", raw):            # a statement at column 0: top level again (self-heals
            stack.clear()                           # after an unbalanced bracket in a regex literal)
        names = _strings_in_use(line, stack) + [m.group("s") for m in EVP.finditer(line)]
        for rx, fixed in C_CALLS.items():
            m = rx.search(line)
            if m:
                names.append(fixed or m.group("s"))
        for name in names:
            if name.lower() in STOP:
                continue
            c = classify_name(name, catalog=cat)
            if any(comp.catalog_key in (None, "PLAINTEXT") for comp in c.components):
                continue
            size = None
            if any(comp.catalog_key == "RSA" for comp in c.components):
                m = MODULUS.search(line)
                size = int(m.group(1)) if m else None
            out.append(Finding(source="code", location=f"{rel}:{i}", algorithm=name, usage=Usage.UNKNOWN,
                               asset=rel, key_size=size, evidence=raw.strip()[:120], context=f"{path.suffix} (regex fallback)",
                               flags={"regex-fallback"}, confidence=0.4, library="unknown"))
    return out
