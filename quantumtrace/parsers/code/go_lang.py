"""Go: the standard library crypto/* packages, golang.org/x/crypto and math/rand.

Go imports one package per algorithm, so a call is identified by
(import path, function): ("crypto/rsa", "GenerateKey"). The local name comes
from the import ("crypto/rand" is used as `rand`, an aliased import as its alias),
which is how `rand.Read` from crypto/rand (fine) and from math/rand (weak) are told apart.
"""
from __future__ import annotations

from ...models import Usage
from .base import FileCtx, Value, in_loop, parse_int, text, walk

HASHES = {   # (path, func) -> algorithm name
    ("crypto/md5", "Sum"): "MD5", ("crypto/md5", "New"): "MD5",
    ("crypto/sha1", "Sum"): "SHA-1", ("crypto/sha1", "New"): "SHA-1",
    ("crypto/sha256", "Sum256"): "SHA-256", ("crypto/sha256", "New"): "SHA-256",
    ("crypto/sha256", "Sum224"): "SHA-224", ("crypto/sha256", "New224"): "SHA-224",
    ("crypto/sha512", "Sum512"): "SHA-512", ("crypto/sha512", "New"): "SHA-512",
    ("crypto/sha512", "Sum384"): "SHA-384", ("crypto/sha512", "New384"): "SHA-384",
}
for _p in ("crypto/sha3", "golang.org/x/crypto/sha3"):
    for _n in ("256", "384", "512"):
        HASHES[(_p, f"Sum{_n}")] = HASHES[(_p, f"New{_n}")] = f"SHA3-{_n}"
CRYPTO_HASH_CONST = {"MD5": "MD5", "SHA1": "SHA1", "SHA224": "SHA224", "SHA256": "SHA256",
                     "SHA384": "SHA384", "SHA512": "SHA512"}
CIPHER_MODES = {"NewGCM": "gcm", "NewGCMWithNonceSize": "gcm", "NewGCMWithTagSize": "gcm",
                "NewGCMWithRandomNonce": "gcm", "NewCBCEncrypter": "cbc", "NewCBCDecrypter": "cbc",
                "NewCTR": "ctr", "NewCFBEncrypter": "cfb", "NewCFBDecrypter": "cfb", "NewOFB": "ofb"}
CURVES = {"P224": "P-224", "P256": "P-256", "P384": "P-384", "P521": "P-521", "X25519": "X25519"}


def visit(ctx: FileCtx) -> None:
    root = ctx.tree.root_node
    ctx.resolver = lambda n: resolve(ctx, n)
    for node in walk(root):
        if node.type == "import_spec":
            path = text(node.child_by_field_name("path")).strip('"`')
            alias = node.child_by_field_name("name")
            local = text(alias) if alias is not None else path.rstrip("/").split("/")[-1]
            if local.startswith("v") and local[1:].isdigit():          # math/rand/v2 -> rand
                local = path.split("/")[-2]
            ctx.imports[local] = path
        elif node.type in ("const_spec", "var_spec"):
            names = node.children_by_field_name("name")
            value = node.child_by_field_name("value")
            values = value.named_children if value is not None else []
            for n, v in zip(names, values):
                ctx.add_const(text(n), v)
        elif node.type in ("short_var_declaration", "assignment_statement"):
            op = node.child_by_field_name("operator")
            if node.type == "assignment_statement" and text(op) != "=":
                continue
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and right is not None and len(left.named_children) == len(right.named_children):
                for n, v in zip(left.named_children, right.named_children):
                    if n.type == "identifier":
                        ctx.add_const(text(n), v)
    for node in walk(root):
        if node.type == "call_expression":
            _call(ctx, node)
        elif node.type == "selector_expression":
            _tls_constant(ctx, node)


TLS_CURVES = {"CurveP256": "secp256r1", "CurveP384": "secp384r1", "CurveP521": "secp521r1", "X25519": "x25519",
              "X25519MLKEM768": "X25519MLKEM768", "SecP256r1MLKEM768": "SecP256r1MLKEM768",
              "SecP384r1MLKEM1024": "SecP384r1MLKEM1024"}


def _tls_constant(ctx: FileCtx, node) -> None:
    """tls.Config{CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}, CurvePreferences: ...}:
    every crypto/tls suite or group constant the code names is an algorithm it enables."""
    operand, field = node.child_by_field_name("operand"), node.child_by_field_name("field")
    if operand is None or operand.type != "identifier" or ctx.imports.get(text(operand)) != "crypto/tls":
        return
    name = text(field)
    if name.startswith("TLS_"):
        ctx.emit(node, name, Usage.PROTOCOL, library="crypto/tls")
    elif name in TLS_CURVES:
        ctx.emit(node, TLS_CURVES[name], Usage.KEY_EXCHANGE, library="crypto/tls")


# ====================================================================== expression evaluation
def resolve(ctx: FileCtx, node) -> Value | None:
    if node is None:
        return None
    t = node.type
    if t == "int_literal":
        n = parse_int(text(node))
        return Value("int", n) if n is not None else None
    if t in ("interpreted_string_literal", "raw_string_literal"):
        return Value("str", text(node)[1:-1])
    if t == "identifier":
        return ctx.resolve_ident(text(node))
    if t == "parenthesized_expression" and node.named_children:
        return resolve(ctx, node.named_children[0])
    if t == "type_conversion_expression" and "byte" in text(node.child_by_field_name("type")):
        s = resolve(ctx, node.child_by_field_name("operand"))       # []byte("0123456789ABCDEF")
        if s and s.kind == "str":
            return Value("bytes", nbytes=len(s.value.encode()), literal=True)
    if t == "binary_expression":
        a, b = resolve(ctx, node.child_by_field_name("left")), resolve(ctx, node.child_by_field_name("right"))
        op = text(node.child_by_field_name("operator"))
        if a and b and a.kind == b.kind == "int" and op in ("*", "+", "-", "/"):
            return Value("int", {"*": a.value * b.value, "+": a.value + b.value,
                                 "-": a.value - b.value, "/": a.value // max(b.value, 1)}[op])
    if t == "call_expression" and text(node.child_by_field_name("function")) == "make":
        args = _args(node)                                           # make([]byte, keyLen)
        if len(args) >= 2 and "byte" in text(args[0]):
            n = resolve(ctx, args[1])
            if n and n.kind == "int":
                return Value("bytes", nbytes=n.value)
    return None


def _args(call):
    a = call.child_by_field_name("arguments")
    return [] if a is None else [c for c in a.named_children if c.type != "comment"]


def _pkg_func(ctx: FileCtx, node) -> tuple[str, str] | None:
    """`aes.NewCipher` -> ("crypto/aes", "NewCipher") if `aes` is an imported package."""
    if node is None or node.type != "selector_expression":
        return None
    operand, field = node.child_by_field_name("operand"), node.child_by_field_name("field")
    if operand is not None and operand.type == "identifier" and text(operand) in ctx.imports:
        return ctx.imports[text(operand)], text(field)
    return None


def _hash_of(ctx: FileCtx, node) -> str | None:
    """sha256.New (a function value) -> 'SHA-256'."""
    pf = _pkg_func(ctx, node)
    return HASHES.get(pf) if pf else None


# ====================================================================== the rules
def _call(ctx: FileCtx, node) -> None:
    func = node.child_by_field_name("function")
    args = _args(node)
    pf = _pkg_func(ctx, func)

    if pf is None:
        # method call on a value: block.Encrypt(dst, src) inside a loop = encrypting block by block by hand
        if func is not None and func.type == "selector_expression" and \
                text(func.child_by_field_name("field")) in ("Encrypt", "Decrypt") and in_loop(node):
            ctx.block_ops_in_loop = True
        return
    path, fn = pf

    if pf in HASHES:
        ctx.emit(node, HASHES[pf], Usage.HASH, library=path)
    elif path == "crypto/hmac" and fn == "New":
        h = _hash_of(ctx, args[0]) if args else None
        bits, literal = ctx.key_bits(args[1] if len(args) > 1 else None)
        ctx.emit(node, f"HMAC-{h.replace('-', '')}" if h else "HMAC", Usage.MAC, library=path,
                 flags={"hardcoded-key"} if literal else (), hmac=True)
    elif path == "crypto/rsa":
        if fn in ("GenerateKey", "GenerateMultiPrimeKey"):
            size = resolve(ctx, args[-1]) if args else None
            ctx.emit(node, "RSA", Usage.UNKNOWN, key_size=size.value if size and size.kind == "int" else None,
                     library=path, family="rsa")
        elif fn.startswith(("Sign", "Verify")):
            ctx.has_sign = True
            hash_arg = next((a for a in args if text(a).startswith("crypto.")), None)
            h = CRYPTO_HASH_CONST.get(text(hash_arg).split(".")[-1]) if hash_arg is not None else None
            ctx.emit(node, f"{h}withRSA" if h else "RSA", Usage.SIGNATURE, library=path, family="rsa")
        elif fn.startswith(("Encrypt", "Decrypt")):
            ctx.has_encrypt = True
            ctx.emit(node, "RSA", Usage.ENCRYPTION, library=path, family="rsa")
    elif path == "crypto/ecdsa":
        if fn == "GenerateKey" and args:
            curve = _pkg_func(ctx, args[0].child_by_field_name("function")) if args[0].type == "call_expression" else None
            ctx.emit(node, CURVES.get(curve[1], "ECDSA") if curve else "ECDSA", Usage.SIGNATURE,
                     library=path, family="ec")
        elif fn.startswith(("Sign", "Verify")):
            ctx.has_sign = True
            ctx.emit(node, "ECDSA", Usage.SIGNATURE, library=path, family="ec")
    elif path == "crypto/ecdh" and fn in CURVES:
        ctx.emit(node, CURVES[fn], Usage.KEY_EXCHANGE, library=path, family="ecdh")
    elif path == "crypto/ed25519" and fn in ("GenerateKey", "Sign", "Verify", "NewKeyFromSeed", "VerifyWithOptions"):
        ctx.emit(node, "Ed25519", Usage.SIGNATURE, library=path)
    elif path in ("crypto/aes", "crypto/des", "crypto/rc4") and fn.startswith("New"):
        name = {"crypto/aes": "AES", "crypto/rc4": "RC4"}.get(path) or (
            "3DES" if fn == "NewTripleDESCipher" else "DES")
        bits, literal = ctx.key_bits(args[0] if args else None)
        ctx.emit(node, name, Usage.ENCRYPTION, key_size=bits if name == "AES" else None, library=path,
                 flags={"hardcoded-key"} if literal else (), family=name.lower())
    elif path == "crypto/cipher" and fn in CIPHER_MODES:
        ctx.modes.add(CIPHER_MODES[fn])
    elif path == "golang.org/x/crypto/chacha20poly1305" and fn in ("New", "NewX"):
        ctx.emit(node, "ChaCha20-Poly1305", Usage.ENCRYPTION, library=path, family="chacha20")
    elif path in ("golang.org/x/crypto/pbkdf2", "crypto/pbkdf2") and fn == "Key":
        h = next((x for x in (_hash_of(ctx, a) for a in args) if x), None)
        ctx.emit(node, f"PBKDF2WithHmac{h.replace('-', '')}" if h else "PBKDF2", Usage.KDF, library=path)
    elif path == "golang.org/x/crypto/curve25519":
        ctx.emit(node, "X25519", Usage.KEY_EXCHANGE, library=path)
    elif path == "crypto/mlkem" and fn.startswith(("GenerateKey", "NewEncapsulationKey", "NewDecapsulationKey")):
        ctx.emit(node, "ML-KEM-1024" if fn.endswith("1024") else "ML-KEM-768", Usage.KEY_EXCHANGE, library=path)
    elif path == "golang.org/x/crypto/bcrypt" and fn == "GenerateFromPassword":
        ctx.emit(node, "bcrypt", Usage.KDF, library=path)
    elif path == "golang.org/x/crypto/scrypt" and fn == "Key":
        ctx.emit(node, "scrypt", Usage.KDF, library=path)
    elif path == "golang.org/x/crypto/argon2" and fn in ("Key", "IDKey"):
        ctx.emit(node, "Argon2", Usage.KDF, library=path)
    elif path in ("crypto/hkdf", "golang.org/x/crypto/hkdf"):
        ctx.emit(node, "HKDF", Usage.KDF, library=path)
    elif path in ("math/rand", "math/rand/v2"):
        ctx.emit(node, "insecure-random", Usage.UNKNOWN, library=path)
