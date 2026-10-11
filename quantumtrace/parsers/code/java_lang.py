"""Java: the JCA (javax.crypto / java.security) and java.util.Random.

In Java the algorithm is a STRING handed to a factory:
    Cipher.getInstance("AES/ECB/PKCS5Padding")    MessageDigest.getInstance("MD5")
    Signature.getInstance("SHA1withRSA")          KeyPairGenerator.getInstance("RSA") + .initialize(1024)
The string is often a constant (Cipher.getInstance(TRANSFORMATION)), so we
resolve identifiers against the file's field / local variable declarations.
"""
from __future__ import annotations

from ...models import Usage
from .base import FileCtx, Value, parse_int, text, walk

JCA = {   # factory class -> (usage, library)
    "Cipher": (Usage.ENCRYPTION, "javax.crypto"),
    "Mac": (Usage.MAC, "javax.crypto"),
    "KeyGenerator": (Usage.ENCRYPTION, "javax.crypto"),
    "KeyAgreement": (Usage.KEY_EXCHANGE, "javax.crypto"),
    "SecretKeyFactory": (Usage.KDF, "javax.crypto"),
    "MessageDigest": (Usage.HASH, "java.security"),
    "Signature": (Usage.SIGNATURE, "java.security"),
    "KeyPairGenerator": (Usage.UNKNOWN, "java.security"),
    "KeyFactory": (Usage.UNKNOWN, "java.security"),
}
FAMILY = {"aes": "aes", "camellia": "camellia", "desede": "3des", "tripledes": "3des", "des": "des",
          "rc4": "rc4", "arcfour": "rc4", "chacha20": "chacha20", "chacha20-poly1305": "chacha20",
          "rsa": "rsa", "dsa": "dsa", "dh": "dh", "diffiehellman": "dh", "ec": "ec", "ecdsa": "ec", "ecdh": "ec",
          "ed25519": "ec", "ed448": "ec", "eddsa": "ec", "x25519": "ecdh", "x448": "ecdh", "xdh": "ecdh"}


def _family(base: str) -> str | None:
    """'sha1withrsa' -> 'rsa', 'sha256withecdsa' -> 'ec', 'aes' -> 'aes'."""
    if "with" in base:
        base = base.rsplit("with", 1)[1]
        base = {"rsa": "rsa", "ecdsa": "ec", "dsa": "dsa", "rsa/pss": "rsa"}.get(base, base)
    return FAMILY.get(base)
BLOCK_CIPHERS_DEFAULT_ECB = {"aes", "des", "desede", "tripledes", "camellia"}


def visit(ctx: FileCtx) -> None:
    root = ctx.tree.root_node
    ctx.resolver = lambda n: resolve(ctx, n)
    for node in walk(root):
        if node.type == "import_declaration":
            name = text(node).replace("import", "", 1).replace("static", "").strip(" ;")
            ctx.imports[name.rsplit(".", 1)[-1]] = name
        elif node.type == "variable_declarator":
            ctx.add_const(text(node.child_by_field_name("name")), node.child_by_field_name("value"))
    variables: dict[str, object] = {}          # variable name -> Finding of the getInstance it holds
    for node in walk(root):
        if node.type == "method_invocation":
            _invocation(ctx, node, variables)
        elif node.type == "object_creation_expression":
            _creation(ctx, node)


# ====================================================================== expression evaluation
def resolve(ctx: FileCtx, node) -> Value | None:
    if node is None:
        return None
    t = node.type
    if t in ("decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal"):
        n = parse_int(text(node))
        return Value("int", n) if n is not None else None
    if t == "string_literal":
        return Value("str", "".join(text(c) for c in node.named_children if c.type in ("string_fragment", "escape_sequence")))
    if t == "identifier":
        return ctx.resolve_ident(text(node))
    if t == "field_access":                            # Constants.KEY or this.KEY
        return ctx.resolve_ident(text(node.child_by_field_name("field")))
    if t in ("parenthesized_expression", "cast_expression") and node.named_children:
        return resolve(ctx, node.named_children[-1])
    if t == "binary_expression":
        a, b = resolve(ctx, node.child_by_field_name("left")), resolve(ctx, node.child_by_field_name("right"))
        op = text(node.child_by_field_name("operator"))
        if a and b and a.kind == b.kind == "int" and op in ("*", "+", "-", "/"):
            return Value("int", {"*": a.value * b.value, "+": a.value + b.value,
                                 "-": a.value - b.value, "/": a.value // max(b.value, 1)}[op])
        if a and b and a.kind == b.kind == "str" and op == "+":
            return Value("str", a.value + b.value)
        return None
    if t == "method_invocation" and text(node.child_by_field_name("name")) == "getBytes":
        s = resolve(ctx, node.child_by_field_name("object"))         # "0123456789ABCDEF".getBytes(UTF_8)
        if s and s.kind == "str":
            return Value("bytes", nbytes=len(s.value.encode()), literal=True)
    if t == "array_creation_expression":                             # new byte[32]
        dims = [c for c in node.named_children if c.type == "dimensions_expr"]
        if dims and dims[0].named_children:
            n = resolve(ctx, dims[0].named_children[0])
            if n and n.kind == "int":
                return Value("bytes", nbytes=n.value)
    return None


def _args(node):
    a = node.child_by_field_name("arguments")
    return [] if a is None else [c for c in a.named_children if "comment" not in c.type]


def _type_name(node) -> str:
    return text(node.child_by_field_name("type")).split("<")[0].rsplit(".", 1)[-1]


def _assigned_variable(node) -> str | None:
    p = node.parent
    if p is not None and p.type == "variable_declarator":
        return text(p.child_by_field_name("name"))
    if p is not None and p.type == "assignment_expression":
        return text(p.child_by_field_name("left")).replace("this.", "")
    return None


# ====================================================================== the rules
def _invocation(ctx: FileCtx, node, variables: dict) -> None:
    obj, name = node.child_by_field_name("object"), text(node.child_by_field_name("name"))
    obj_text = text(obj).rsplit(".", 1)[-1] if obj is not None else ""
    args = _args(node)

    if name == "getInstance" and obj_text in JCA and args:
        v = resolve(ctx, args[0])
        if not v or v.kind != "str":
            ctx.emit(node, f"{obj_text}:unresolved", JCA[obj_text][0], library=JCA[obj_text][1], confidence=0.3)
            return
        alg = v.value
        usage, lib = JCA[obj_text]
        base = alg.split("/")[0].lower()
        mode, flags = None, set()
        if obj_text == "Cipher":
            if base in ("rsa", "rsa/ecb") or base.startswith("rsa"):
                usage = Usage.ENCRYPTION
                ctx.has_encrypt = True
            elif "/" not in alg and base in BLOCK_CIPHERS_DEFAULT_ECB:
                mode, flags = "ecb", {"default-mode-ecb"}         # JCA default for "AES" is AES/ECB/PKCS5Padding
        if obj_text == "Signature":
            ctx.has_sign = True
        if obj_text in ("Mac", "KeyGenerator") and base.startswith("hmac"):
            usage = Usage.MAC
        if obj_text == "SecretKeyFactory" and not base.startswith("pbkdf2") and not base.startswith("pbe"):
            usage = Usage.ENCRYPTION
        f = ctx.emit(node, alg, usage, mode=mode, flags=flags, library=lib, family=_family(base),
                     hmac=obj_text == "Mac")
        var = _assigned_variable(node)
        if var:
            variables[var] = (obj_text, f, base)
        return

    # generator.initialize(1024) / keyGen.init(256): key size for the generator created above
    if name in ("initialize", "init") and obj is not None and obj.type == "identifier" and text(obj) in variables:
        cls, f, base = variables[text(obj)]
        if cls in ("KeyPairGenerator", "KeyGenerator") and args:
            v = resolve(ctx, args[0])
            if v and v.kind == "int":
                f.key_size = v.value
                ctx.add_hint(FAMILY.get(base, base), v.value)
        return

    if obj_text == "Math" and name == "random":
        ctx.emit(node, "insecure-random", Usage.UNKNOWN, library="java.lang.Math")
    elif obj_text == "ThreadLocalRandom" and name == "current":
        ctx.emit(node, "insecure-random", Usage.UNKNOWN, library="java.util.concurrent")


def _creation(ctx: FileCtx, node) -> None:
    cls = _type_name(node)
    args = _args(node)
    if cls == "SecretKeySpec" and len(args) >= 2:
        alg = resolve(ctx, args[-1])
        if not alg or alg.kind != "str":
            return
        bits, literal = ctx.key_bits(args[0])
        base = alg.value.split("/")[0].lower()
        is_mac = base.startswith("hmac")
        ctx.emit(node, alg.value, Usage.MAC if is_mac else Usage.ENCRYPTION,
                 key_size=None if is_mac else bits, flags={"hardcoded-key"} if literal else (),
                 library="javax.crypto", family=None if is_mac else FAMILY.get(base))
        if not is_mac:
            ctx.add_hint(FAMILY.get(base, base), bits, literal)
    elif cls == "ECGenParameterSpec" and args:
        curve = resolve(ctx, args[0])
        if curve and curve.kind == "str":
            ctx.emit(node, curve.value, Usage.UNKNOWN, library="java.security", family="ec")
    elif cls == "Random" and (ctx.imports.get("Random", "java.util.Random") == "java.util.Random"
                              or text(node.child_by_field_name("type")) == "java.util.Random"):
        ctx.emit(node, "insecure-random", Usage.UNKNOWN, library="java.util")
