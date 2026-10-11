"""Python: hashlib, hmac, random, `cryptography` (pyca) and PyCryptodome.

Calls are matched on their QUALIFIED name, built from the file's imports:
    import hashlib as h          ->  h.md5(...)          == hashlib.md5
    from ...ciphers import algorithms -> algorithms.AES(k) == cryptography.hazmat.primitives.ciphers.algorithms.AES
so aliasing an import cannot hide a call, and a local variable that happens to be
called `md5` is not mistaken for hashlib.md5.
"""
from __future__ import annotations

import ast
import re

from ...models import Usage
from .base import FileCtx, Value, parse_int, text, walk

HASH_NAMES = re.compile(r"^(md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs]|shake_\d+)$")
CRYPTO_HASHES = re.compile(r"\.hazmat\.primitives\.hashes\.(\w+)$")
CRYPTO_ALGS = re.compile(r"\.hazmat\.primitives\.ciphers\.algorithms\.(\w+)$")
CRYPTO_AEAD = re.compile(r"\.hazmat\.primitives\.ciphers\.aead\.(AESGCM|AESCCM|AESOCB3|AESSIV|AESGCMSIV|ChaCha20Poly1305)$")
CRYPTO_ASYM = re.compile(r"\.hazmat\.primitives\.asymmetric\.(\w+)\.(\w+(?:\.\w+)?)$")
CRYPTO_KDF = re.compile(r"\.hazmat\.primitives\.kdf\.\w+\.(PBKDF2HMAC|Scrypt|HKDF|HKDFExpand|Argon2id|Argon2i|Argon2d)$")
PYCRYPTO = re.compile(r"^Crypto\.(Cipher|Hash|PublicKey|Signature|Protocol\.KDF)\.(\w+)(?:\.(\w+))?$")
WEAK_RANDOM = re.compile(r"^random\.(random|randint|randrange|getrandbits|choice|choices|randbytes|shuffle|sample|uniform)$")
BUILTINS = {"bytes", "bytearray"}
JWT_CALLS = {"jwt.encode", "jwt.decode", "jose.jwt.encode", "jose.jwt.decode", "jose.jws.sign", "jose.jws.verify"}
NOT_HASHES = {"Hash", "HashAlgorithm", "HashContext", "ExtendableOutputFunction"}
PYCRYPTO_CIPHER = {"AES": "AES", "DES": "DES", "DES3": "3DES", "ARC4": "RC4", "ChaCha20": "ChaCha20",
                   "ChaCha20_Poly1305": "ChaCha20-Poly1305", "Blowfish": "Blowfish", "CAST": "CAST5"}
FAMILY = {"AES": "aes", "AES128": "aes", "AES256": "aes", "Camellia": "camellia", "TripleDES": "3des",
          "3DES": "3des", "DES": "des", "ARC4": "rc4", "RC4": "rc4", "ChaCha20": "chacha20"}


def visit(ctx: FileCtx) -> None:
    root = ctx.tree.root_node
    ctx.resolver = lambda n: resolve(ctx, n)
    _collect_imports(ctx, root)
    _collect_consts(ctx, root)
    for node in walk(root):
        if node.type == "call":
            _call(ctx, node)


# ====================================================================== imports / constants
def _collect_imports(ctx: FileCtx, root) -> None:
    for node in walk(root):
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "aliased_import":
                    ctx.imports[text(child.child_by_field_name("alias"))] = text(child.child_by_field_name("name"))
                elif child.type == "dotted_name":
                    name = text(child)
                    ctx.imports[name.split(".")[0]] = name.split(".")[0]
        elif node.type == "import_from_statement":
            module = text(node.child_by_field_name("module_name")).replace("Cryptodome", "Crypto")
            for child in node.children_by_field_name("name"):
                if child.type == "aliased_import":
                    ctx.imports[text(child.child_by_field_name("alias"))] = \
                        f"{module}.{text(child.child_by_field_name('name'))}"
                else:
                    ctx.imports[text(child)] = f"{module}.{text(child)}"


def _collect_consts(ctx: FileCtx, root) -> None:
    for node in walk(root):
        if node.type == "assignment":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and left.type == "identifier":
                ctx.add_const(text(left), right)
        elif node.type in ("default_parameter", "typed_default_parameter"):
            ctx.add_const(text(node.child_by_field_name("name")), node.child_by_field_name("value"))


def qualify(ctx: FileCtx, func) -> str:
    """`algorithms.AES` -> 'cryptography.hazmat.primitives.ciphers.algorithms.AES' (via imports)."""
    if func is None or func.type not in ("identifier", "attribute"):
        return ""
    name = text(func)
    if not re.fullmatch(r"[\w.]+", name):
        return ""
    head, _, rest = name.partition(".")
    if head in ctx.imports:
        head = ctx.imports[head]
    elif head not in BUILTINS:
        return ""                 # not imported: a local object that happens to be called `hashlib` / `md5`
    return f"{head}.{rest}" if rest else head


# ====================================================================== expression evaluation
def resolve(ctx: FileCtx, node) -> Value | None:
    if node is None:
        return None
    t = node.type
    if t == "integer":
        n = parse_int(text(node))
        return Value("int", n) if n is not None else None
    if t == "string":
        try:
            v = ast.literal_eval(text(node))
        except (ValueError, SyntaxError):
            return None
        if isinstance(v, bytes):
            return Value("bytes", nbytes=len(v), literal=True)
        return Value("str", v)
    if t == "identifier":
        return ctx.resolve_ident(text(node))
    if t == "parenthesized_expression" and node.named_children:
        return resolve(ctx, node.named_children[0])
    if t == "binary_expression":
        a, b = resolve(ctx, node.child_by_field_name("left")), resolve(ctx, node.child_by_field_name("right"))
        op = text(node.child_by_field_name("operator"))
        if a and b and a.kind == b.kind == "int" and op in ("*", "+", "-", "//"):
            return Value("int", {"*": a.value * b.value, "+": a.value + b.value,
                                 "-": a.value - b.value, "//": a.value // max(b.value, 1)}[op])
        return None
    if t == "call":
        q = qualify(ctx, node.child_by_field_name("function"))
        arg = _arg(node, 0)
        if q in ("os.urandom", "secrets.token_bytes", "Crypto.Random.get_random_bytes", "bytes", "bytearray"):
            n = resolve(ctx, arg)
            if n and n.kind == "int":
                return Value("bytes", nbytes=n.value)
        func = node.child_by_field_name("function")
        if q.endswith(".generate_key") and CRYPTO_AEAD.search(q[:-len(".generate_key")]):   # AESGCM.generate_key(bit_length=128)
            n = resolve(ctx, _arg(node, 0, "bit_length"))
            if n and n.kind == "int" and n.value % 8 == 0:
                return Value("bytes", nbytes=n.value // 8)
        if func is not None and func.type == "attribute" and text(func.child_by_field_name("attribute")) == "encode":
            s = resolve(ctx, func.child_by_field_name("object"))
            if s and s.kind == "str":
                return Value("bytes", nbytes=len(s.value.encode()), literal=True)
    return None


def _args(call):
    args = call.child_by_field_name("arguments")
    return [] if args is None else [a for a in args.named_children if a.type != "comment"]


def _arg(call, pos: int, kw: str | None = None):
    positional = [a for a in _args(call) if a.type not in ("keyword_argument", "list_splat", "dictionary_splat")]
    if kw:
        for a in _args(call):
            if a.type == "keyword_argument" and text(a.child_by_field_name("name")) == kw:
                return a.child_by_field_name("value")
    return positional[pos] if pos < len(positional) else None


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


# ====================================================================== the rules
def _call(ctx: FileCtx, node) -> None:
    func = node.child_by_field_name("function")
    q = qualify(ctx, func)

    # usage signals for asymmetric keys (method calls on key objects we cannot type)
    if func is not None and func.type == "attribute":
        attr = text(func.child_by_field_name("attribute"))
        if attr in ("sign", "verify") and not q.startswith(("hmac.", "hashlib.")):
            ctx.has_sign = True
    if q.endswith(".asymmetric.padding.OAEP") or q == "Crypto.Cipher.PKCS1_OAEP.new":
        ctx.has_encrypt = True

    if not q:
        return

    # --- hashlib --------------------------------------------------------------
    if q.startswith("hashlib."):
        name = _last(q)
        if HASH_NAMES.match(name):
            ctx.emit(node, name, Usage.HASH, library="hashlib")
        elif name == "new":
            v = resolve(ctx, _arg(node, 0, "name"))
            if v and v.kind == "str":
                ctx.emit(node, v.value, Usage.HASH, library="hashlib")
        elif name == "pbkdf2_hmac":
            v = resolve(ctx, _arg(node, 0, "hash_name"))
            prf = v.value if v and v.kind == "str" else "sha1"
            ctx.emit(node, f"PBKDF2WithHmac{prf.replace('-', '').upper()}", Usage.KDF, library="hashlib")
        elif name == "scrypt":
            ctx.emit(node, "scrypt", Usage.KDF, library="hashlib")
        return

    # --- hmac -----------------------------------------------------------------
    if q in ("hmac.new", "hmac.HMAC", "hmac.digest"):
        digest = _arg(node, 2, "digestmod" if q != "hmac.digest" else "digest")
        h = _digest_name(ctx, digest)
        bits, literal = ctx.key_bits(_arg(node, 0, "key"))
        ctx.emit(node, f"HMAC-{h.upper().replace('_', '-')}" if h else "HMAC", Usage.MAC, library="hmac",
                 flags={"hardcoded-key"} if literal else (), hmac=True)
        return

    # --- random (not cryptographically secure) --------------------------------
    if WEAK_RANDOM.match(q):
        ctx.emit(node, "insecure-random", Usage.UNKNOWN, library="random")
        return

    # --- JWT / JWS (PyJWT, python-jose): the "alg" names a signature / MAC algorithm ----
    if q in JWT_CALLS:
        enc = q.endswith(("encode", "sign"))
        node_alg = _arg(node, 2 if enc else 99, "algorithm" if enc else "algorithms")
        names = _strings(ctx, node_alg)
        if enc and node_alg is None:
            names = ["HS256"]                              # PyJWT / python-jose default
        for n in names:
            ctx.emit(node, n, Usage.SIGNATURE, library=q.split(".")[0])
        if any(n.upper().startswith(("RS", "PS", "ES", "ED")) for n in names):
            ctx.has_sign = True
        return

    # --- cryptography: Fernet = AES-128-CBC + HMAC-SHA256 (spec) ----------------
    if q == "cryptography.fernet.Fernet":
        ctx.emit(node, "AES", Usage.ENCRYPTION, key_size=128, mode="cbc", library="cryptography", family="aes")
        ctx.emit(node, "HMAC-SHA256", Usage.MAC, library="cryptography")
        return

    lib = "cryptography" if ".hazmat." in q else "pycryptodome" if q.startswith("Crypto.") else ""

    # --- cryptography: hashes -------------------------------------------------
    m = CRYPTO_HASHES.search(q)
    if m and m.group(1) not in NOT_HASHES:
        ctx.emit(node, m.group(1), Usage.HASH, library=lib)
        return

    # --- cryptography: Cipher(algorithms.X(key), modes.Y(...)) ------------------
    m = CRYPTO_ALGS.search(q)
    if m:
        name = m.group(1)
        bits, literal = ctx.key_bits(_arg(node, 0, "key"))
        mode = None
        parent_call = node.parent.parent if node.parent is not None else None      # argument_list -> call
        if parent_call is not None and parent_call.type == "call" and _last(qualify(
                ctx, parent_call.child_by_field_name("function"))) == "Cipher":
            mode_node = _arg(parent_call, 1, "mode")
            if mode_node is not None and mode_node.type == "call":
                mode = _last(qualify(ctx, mode_node.child_by_field_name("function"))).lower()
        ctx.emit(node, name, Usage.ENCRYPTION, key_size=bits, mode=mode, library=lib,
                 flags={"hardcoded-key"} if literal else (), family=FAMILY.get(name))
        return

    m = CRYPTO_AEAD.search(q)
    if m:
        bits, literal = ctx.key_bits(_arg(node, 0, "key"))
        ctx.emit(node, m.group(1), Usage.ENCRYPTION, key_size=bits, library=lib,
                 flags={"hardcoded-key"} if literal else (),
                 family="chacha20" if m.group(1).startswith("ChaCha") else "aes")
        return

    # --- cryptography: asymmetric -----------------------------------------------
    m = CRYPTO_ASYM.search(q)
    if m:
        module, attr = m.group(1), m.group(2)
        if module in ("rsa", "dsa") and attr == "generate_private_key":
            size = resolve(ctx, _arg(node, 1, "key_size"))
            ctx.emit(node, module.upper(), Usage.UNKNOWN, key_size=size.value if size and size.kind == "int" else None,
                     library=lib, family=module)
        elif module == "dh" and attr == "generate_parameters":
            size = resolve(ctx, _arg(node, 1, "key_size"))
            ctx.emit(node, "DH", Usage.KEY_EXCHANGE, key_size=size.value if size and size.kind == "int" else None,
                     library=lib, family="dh")
        elif module == "ec" and attr in ("generate_private_key", "derive_private_key"):
            curve = _arg(node, 0 if attr == "generate_private_key" else 1, "curve")
            name = _last(qualify(ctx, curve.child_by_field_name("function"))) if curve is not None and curve.type == "call" else "EC"
            ctx.emit(node, name, Usage.UNKNOWN, library=lib, family="ec")
        elif module == "ec" and attr in ("ECDH", "ECDSA"):
            ctx.emit(node, attr, Usage.KEY_EXCHANGE if attr == "ECDH" else Usage.SIGNATURE, library=lib)
        elif module in ("ed25519", "ed448", "x25519", "x448") and attr.endswith(("generate", "from_private_bytes")):
            name = {"ed25519": "Ed25519", "ed448": "Ed448", "x25519": "X25519", "x448": "X448"}[module]
            ctx.emit(node, name, Usage.SIGNATURE if module.startswith("ed") else Usage.KEY_EXCHANGE, library=lib)
        return

    # --- cryptography: KDFs -----------------------------------------------------
    m = CRYPTO_KDF.search(q)
    if m:
        ctx.emit(node, m.group(1), Usage.KDF, library=lib)
        return

    # --- PyCryptodome -------------------------------------------------------------
    m = PYCRYPTO.match(q)
    if m:
        pkg, mod, fn = m.groups()
        if pkg == "Cipher" and fn == "new" and mod in PYCRYPTO_CIPHER:
            name = PYCRYPTO_CIPHER[mod]
            bits, literal = ctx.key_bits(_arg(node, 0, "key"))
            mode_node = _arg(node, 1, "mode")
            mode = _last(text(mode_node)).replace("MODE_", "").lower() if mode_node is not None else None
            ctx.emit(node, name, Usage.ENCRYPTION, key_size=bits, mode=mode, library=lib,
                     flags={"hardcoded-key"} if literal else (), family=FAMILY.get(name))
        elif pkg == "Cipher" and mod == "PKCS1_OAEP" and fn == "new":
            ctx.emit(node, "RSA", Usage.ENCRYPTION, library=lib, family="rsa")
        elif pkg == "Signature" and fn == "new":
            ctx.emit(node, "ECDSA" if mod == "DSS" else "RSA", Usage.SIGNATURE, library=lib,
                     family="ecdsa" if mod == "DSS" else "rsa")
            ctx.has_sign = True
        elif pkg == "PublicKey" and fn in ("generate", "construct") and mod in ("RSA", "DSA", "ECC"):
            if mod == "ECC":
                curve = resolve(ctx, _arg(node, 0, "curve"))
                ctx.emit(node, curve.value if curve and curve.kind == "str" else "ECDSA", Usage.UNKNOWN,
                         library=lib, family="ec")
            else:
                size = resolve(ctx, _arg(node, 0, "bits"))
                ctx.emit(node, mod, Usage.UNKNOWN, key_size=size.value if size and size.kind == "int" else None,
                         library=lib, family=mod.lower())
        elif pkg == "Hash" and fn == "new":
            ctx.emit(node, mod, Usage.HASH, library=lib)
        elif pkg == "Protocol.KDF" and mod in ("PBKDF2", "scrypt", "HKDF", "bcrypt"):
            ctx.emit(node, mod, Usage.KDF, library=lib)


def _strings(ctx: FileCtx, node) -> list[str]:
    """'RS256' / ALG / ["RS256", "ES256"] -> the string values that can be resolved."""
    if node is None:
        return []
    if node.type in ("list", "tuple", "set"):
        return [s for c in node.named_children for s in _strings(ctx, c)]
    if node.type == "identifier":                  # ALGS = ["RS256", "ES256"] (one assignment only)
        defs = ctx.consts.get(text(node), [])
        if len(defs) == 1 and defs[0].type in ("list", "tuple", "set"):
            return _strings(ctx, defs[0])
    v = resolve(ctx, node)
    return [v.value] if v and v.kind == "str" and v.value else []


def _digest_name(ctx: FileCtx, node) -> str | None:
    """hmac.new(..., digestmod=hashlib.sha256 | "sha256" | sha256) -> 'sha256'."""
    if node is None:
        return None
    if node.type in ("attribute", "identifier"):
        q = qualify(ctx, node)
        return _last(q) if q else None
    if node.type == "call":                         # cryptography style: hashes.SHA256()
        return _last(qualify(ctx, node.child_by_field_name("function")))
    v = resolve(ctx, node)
    return v.value if v and v.kind == "str" else None
