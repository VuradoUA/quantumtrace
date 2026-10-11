"""Shared machinery for the code scanner (all languages).

Each language module walks its tree-sitter AST and calls `ctx.emit(...)` for
every crypto API call it recognises. `finalize(ctx)` then applies the
file-level reasoning that one call on its own cannot do:

  * key-size inference   AESGCM(key) says nothing about the size; a constant
                         KEY_LEN = 32 or SecretKeySpec(16 bytes, "AES") does
  * mode inference       Go: aes.NewCipher + cipher.NewGCM elsewhere = GCM;
                         block.Encrypt in a loop with no mode = hand-rolled ECB
  * usage inference      an RSA key in a file that calls .sign() is a signing key
  * hand-rolled PBKDF2   HMAC inside a loop + XOR accumulation in one function
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ...models import Finding, Usage

LOOP_TYPES = {"for_statement", "while_statement", "enhanced_for_statement", "do_statement"}
FUNC_TYPES = {"function_definition", "method_declaration", "constructor_declaration",
              "function_declaration", "method_declaration", "func_literal", "lambda_expression"}
XOR_ASSIGN_TYPES = {"augmented_assignment", "assignment_expression", "assignment_statement"}

PASSWORD = re.compile(r"passw|pwd|passphrase|credential", re.I)
KEY_BITS_NAME = re.compile(r"key\w*bits$", re.I)                    # KEY_BITS, keyLenBits
KEY_BYTES_NAME = re.compile(r"key\w*(len|length|size|bytes)$", re.I)  # KEY_LEN, keyLen, key_size
KEY_NAME = re.compile(r"key", re.I)                                  # EXPORT_KEY, exportKey, key

SYMMETRIC_FAMILIES = {"aes", "camellia", "3des", "des", "rc4", "chacha20"}
SIZED_SYMMETRIC = {"aes", "camellia"}                  # tier depends on key size
VALID_KEY_BITS = {"aes": {128, 192, 256}, "camellia": {128, 192, 256}}   # a hint outside these is about another key
ASYMMETRIC_FAMILIES = {"rsa", "dsa", "dh", "ec", "ecdsa", "ecdh"}
HASH_LIKE = {Usage.HASH, Usage.KDF}


@dataclass
class Value:
    """What an expression evaluates to, as far as we can tell statically."""
    kind: str                      # "int" | "str" | "bytes"
    value: object = None           # int / str (None for bytes)
    nbytes: int | None = None      # for bytes: length
    literal: bool = False          # bytes written directly in the source -> hardcoded


@dataclass
class Hit:
    finding: Finding
    node: object                   # the tree-sitter node of the call
    family: str | None = None      # "aes", "rsa", ... for file-level inference
    hmac: bool = False


@dataclass
class FileCtx:
    path: Path
    rel: str
    lang: str
    src: bytes
    tree: object
    imports: dict[str, str] = field(default_factory=dict)       # local name -> qualified name
    consts: dict[str, list] = field(default_factory=dict)       # name -> [value nodes]
    hits: list[Hit] = field(default_factory=list)
    hints: dict[str, set] = field(default_factory=dict)         # family -> {(bits, literal)}
    has_sign: bool = False
    has_encrypt: bool = False
    modes: set[str] = field(default_factory=set)                # modes constructed separately (Go cipher.NewGCM)
    block_ops_in_loop: bool = False                             # Go: block.Encrypt(...) inside a loop
    resolver: object = None                                     # language-specific expression evaluator
    _resolving: set = field(default_factory=set)

    # ------------------------------------------------------------------ emitting
    def emit(self, node, algorithm: str, usage: Usage, *, key_size: int | None = None,
             mode: str | None = None, flags=(), family: str | None = None, library: str = "",
             confidence: float = 1.0, hmac: bool = False) -> Finding:
        func = node if node.type in FUNC_TYPES else enclosing_function(node)
        fname = function_name(func)
        flags = set(flags)
        if usage in HASH_LIKE and func is not None and (
                PASSWORD.search(fname or "") or PASSWORD.search(params_text(func))):
            flags.add("password-hash")
        f = Finding(source="code", location=f"{self.rel}:{node.start_point[0] + 1}", algorithm=algorithm,
                    usage=usage, asset=self.rel, key_size=key_size, mode=mode, evidence=first_line(node),
                    context=f"{self.lang}, in {fname + '()' if fname else 'module level'}",
                    flags=flags, confidence=confidence, library=library)
        self.hits.append(Hit(f, node, family, hmac))
        return f

    def add_hint(self, family: str, bits: int | None, literal: bool = False) -> None:
        if bits:
            self.hints.setdefault(family, set()).add((bits, literal))

    # ------------------------------------------------------------------ constants
    def add_const(self, name: str, value_node) -> None:
        if name and value_node is not None:
            self.consts.setdefault(name, []).append(value_node)

    def resolve_ident(self, name: str) -> Value | None:
        """An identifier resolves only if EVERY assignment to it gives the same value."""
        defs = self.consts.get(name)
        if not defs or name in self._resolving:
            return None
        self._resolving.add(name)
        try:
            values = [self.resolver(d) for d in defs]
        finally:
            self._resolving.discard(name)
        if any(v is None for v in values):
            return None
        first = values[0]
        return first if all(v == first for v in values) else None

    def key_bits(self, node) -> tuple[int | None, bool]:
        """Key argument -> (bits, hardcoded?)."""
        if node is None:
            return None, False
        v = self.resolver(node)
        if v and v.kind == "bytes" and v.nbytes:
            return v.nbytes * 8, v.literal
        if v and v.kind == "str" and isinstance(v.value, str):      # Java/Go string keys
            return len(v.value.encode()) * 8, True
        return None, False


# ====================================================================== tree helpers
def text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def first_line(node, limit: int = 120) -> str:
    t = text(node).strip().splitlines()[0] if text(node).strip() else ""
    return t if len(t) <= limit else t[:limit - 3] + "..."


def walk(node):
    yield node
    for c in node.children:
        yield from walk(c)


def enclosing_function(node):
    n = node.parent
    while n is not None:
        if n.type in FUNC_TYPES:
            return n
        n = n.parent
    return None


def function_name(func) -> str:
    if func is None:
        return ""
    name = func.child_by_field_name("name")
    return text(name) if name is not None else "<anonymous>"


def params_text(func) -> str:
    p = func.child_by_field_name("parameters") if func is not None else None
    return text(p)


def in_loop(node) -> bool:
    n = node.parent
    while n is not None and n.type not in FUNC_TYPES:
        if n.type in LOOP_TYPES:
            return True
        n = n.parent
    return False


def parse_int(s: str) -> int | None:
    s = s.replace("_", "").rstrip("lL")
    try:
        return int(s, 0)
    except ValueError:
        return None


# ====================================================================== file-level reasoning
def collect_name_hints(ctx: FileCtx) -> None:
    """Constants whose NAME says they are a key size or a key (KEY_LEN = 32, EXPORT_KEY = b'...')."""
    for name in list(ctx.consts):
        v = ctx.resolve_ident(name)
        if v is None:
            continue
        if v.kind == "int" and KEY_BITS_NAME.search(name):
            ctx.add_hint("*", v.value)
        elif v.kind == "int" and KEY_BYTES_NAME.search(name) and v.value <= 128:
            ctx.add_hint("*", v.value * 8)
        elif v.kind == "bytes" and v.literal and v.nbytes and KEY_NAME.search(name):
            ctx.add_hint("*", v.nbytes * 8, literal=True)


def finalize(ctx: FileCtx) -> list[Finding]:
    collect_name_hints(ctx)

    # 1. cipher mode: Go modes are separate objects; no mode + block ops in a loop = hand-rolled ECB
    for h in ctx.hits:
        f = h.finding
        if h.family in SYMMETRIC_FAMILIES and h.family not in ("rc4", "chacha20") and not f.mode \
                and ctx.lang == "go":
            if ctx.modes:
                if len(ctx.modes) == 1:
                    f.mode = next(iter(ctx.modes))
            elif ctx.block_ops_in_loop:
                f.mode = "ecb"
                f.flags.add("hand-rolled-mode")

    # 2. symmetric key size: family hints (SecretKeySpec, KeyGenerator.init) first, then name hints
    for h in ctx.hits:
        f = h.finding
        if h.family in SIZED_SYMMETRIC and f.key_size is None:
            valid = VALID_KEY_BITS[h.family]
            cands = {c for c in ctx.hints.get(h.family, set()) if c[0] in valid} or \
                {c for c in ctx.hints.get("*", set()) if c[0] in valid}      # TOKEN_KEY_BITS = 2048 is RSA's
            sizes = {b for b, _ in cands}
            if len(sizes) == 1:
                f.key_size = sizes.pop()
                f.flags.add("key-size-inferred")
                f.confidence = min(f.confidence, 0.8)
                if any(lit for _, lit in cands):
                    f.flags.add("hardcoded-key")

    # 3. asymmetric key size: reuse the size from the key generation call in the same file
    for fam in ASYMMETRIC_FAMILIES:
        sizes = {h.finding.key_size for h in ctx.hits if h.family == fam and h.finding.key_size}
        if len(sizes) == 1:
            size = next(iter(sizes))
            for h in ctx.hits:
                if h.family == fam and h.finding.key_size is None:
                    h.finding.key_size = size
                    h.finding.flags.add("key-size-inferred")

    # 4. usage: a key-generation call says nothing about what the key is FOR
    for h in ctx.hits:
        if h.family in ASYMMETRIC_FAMILIES and h.finding.usage is Usage.UNKNOWN:
            if ctx.has_encrypt:                    # conservative: encryption = HNDL exposure
                h.finding.usage = Usage.ENCRYPTION
            elif ctx.has_sign:
                h.finding.usage = Usage.SIGNATURE

    # 5. hand-rolled PBKDF2: HMAC called in a loop + XOR accumulation, inside one function
    done = set()
    for h in list(ctx.hits):
        if not h.hmac or not in_loop(h.node):
            continue
        func = enclosing_function(h.node)
        if func is None or func.id in done:
            continue
        if any(n.type in XOR_ASSIGN_TYPES and any(c.type == "^=" for c in n.children) and in_loop(n)
               for n in walk(func)):
            done.add(func.id)
            ctx.emit(func, "PBKDF2", Usage.KDF, flags={"hand-rolled-kdf"}, library=h.finding.library,
                     confidence=0.8)

    return [h.finding for h in ctx.hits]
