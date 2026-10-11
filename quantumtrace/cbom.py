"""CycloneDX 1.6 Cryptography Bill of Materials (decision 9).

Built as plain dicts from the classified findings, then checked against the OFFICIAL
CycloneDX 1.6 JSON schema (cyclonedx-python-lib) plus our own reference-integrity check.

What goes where (CycloneDX 1.6 "cryptographic-asset" components):

    algorithm                one per distinct algorithm (RSA-2048, AES-128-GCM, X25519MLKEM768 ...);
                             composite names (SHA256withRSA, diffie-hellman-group14-sha1) are their own
                             algorithm and `dependsOn` their parts
    certificate              one per certificate (SHA-256 fingerprint / ACM ARN); signatureAlgorithmRef +
                             subjectPublicKeyRef -> a related-crypto-material public key
    related-crypto-material  keys: KMS keys, private / public key files, SSH keys
    protocol                 one per distinct TLS / SSH profile (version + cipher suites + groups)
    library components       declared libraries (purl) and the platform APIs code uses (hashlib, JCA, Go stdlib)

Traceability: every crypto component has `evidence.occurrences` (file + line, or JSON path, or PCAP
stream/frame) and quantumtrace:* properties (tier, HNDL, flags, PQC replacement, FIPS standard).
`dependencies`: target -> assets (files / services) -> what they use; libraries `provides` algorithms.
`definitions.standards` declares NIST FIPS 203 / 204 / 205.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

from . import __version__
from .catalog import Catalog, load_catalog, norm
from .models import ComponentResult, Finding, Tier, Usage
from .purl import parse_purl
from .score import RiskScore

SPEC_VERSION = "1.6"
PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
              "key-agree", "kem", "ae", "combiner", "other", "unknown"}
MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
CURVES = {"EC-P256": "secp256r1", "EC-P384": "secp384r1", "EC-P521": "secp521r1", "EC-SECP256K1": "secp256k1",
          "SM2": "sm2p256v1", "X25519": "curve25519", "X448": "curve448", "Ed25519": "edwards25519",
          "Ed448": "edwards448"}
AES_MODE_ARC = {"ecb": 1, "cbc": 2, "ofb": 3, "cfb": 4, "gcm": 6, "ccm": 7}     # NIST CSOR 2.16.840.1.101.3.4.1.x
AES_BITS_ARC = {128: 0, 192: 20, 256: 40}
STANDARDS = {
    "FIPS 203": ("standard/nist-fips-203", "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)", "203"),
    "FIPS 204": ("standard/nist-fips-204", "Module-Lattice-Based Digital Signature Standard (ML-DSA)", "204"),
    "FIPS 205": ("standard/nist-fips-205", "Stateless Hash-Based Digital Signature Standard (SLH-DSA)", "205"),
}
PSEUDO_FLAGS = {"incomplete-handshake", "unparseable", "password-protected", "unknown-policy"}
PY_STDLIB = {"hashlib", "hmac", "random", "secrets", "os", "ssl"}
LIB_PLATFORMS = {"python-stdlib": "Python standard library", "java-jca": "Java Cryptography Architecture (JDK)",
                 "go-stdlib": "Go standard library"}


# ====================================================================== small helpers
def _iso(value) -> str | None:
    """Anything date-like -> RFC 3339 'YYYY-MM-DDTHH:MM:SSZ' (the schema's date-time), else None."""
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def split_location(loc: str) -> tuple[str, int | None, str]:
    """'python/x.py:6' -> ('python/x.py', 6, ''); 'kms.json:$.Keys[2]' -> ('kms.json', None, '$.Keys[2]');
    'network.pcap:stream 4, frame 31' -> ('network.pcap', None, 'stream 4, frame 31')."""
    m = re.match(r"^(.*?):(\d+)$", loc)
    if m:
        return m.group(1), int(m.group(2)), ""
    m = re.match(r"^(.*?):(\$.*|stream .*)$", loc)
    if m:
        return m.group(1), None, m.group(2)
    return loc, None, ""


def _functions(primitive: str, role: Usage) -> list[str]:
    if primitive in ("hash", "xof", "mac", "kdf", "drbg"):
        role = Usage.UNKNOWN                         # a hash inside SHA256withRSA still only digests
    if role is Usage.KEY_EXCHANGE:
        return ["keygen", "encapsulate", "decapsulate"] if primitive == "kem" else ["keygen", "keyderive"]
    if role is Usage.ENCRYPTION:
        return ["encrypt", "decrypt"]
    if role in (Usage.SIGNATURE, Usage.CERTIFICATE):
        return ["sign", "verify"]
    return {"hash": ["digest"], "xof": ["digest"], "mac": ["tag"], "kdf": ["keyderive"], "drbg": ["generate"],
            "kem": ["encapsulate", "decapsulate"], "key-agree": ["keyderive"], "signature": ["sign", "verify"],
            "ae": ["encrypt", "decrypt"], "block-cipher": ["encrypt", "decrypt"],
            "stream-cipher": ["encrypt", "decrypt"], "pke": ["encrypt", "decrypt"]}.get(primitive, [])


def _oid(comp: ComponentResult) -> str | None:
    """Catalog OID, made precise for AES (the catalog only has the AES arc)."""
    if comp.catalog_key == "AES":
        if comp.bits in AES_BITS_ARC and comp.mode in AES_MODE_ARC:
            return f"2.16.840.1.101.3.4.1.{AES_BITS_ARC[comp.bits] + AES_MODE_ARC[comp.mode]}"
        return None
    return comp.oid


def _param_set(comp: ComponentResult) -> str | None:
    m = re.match(r"^(ML-KEM|ML-DSA)-(\d+)$", comp.name)
    if m:
        return m.group(2)
    return str(comp.bits) if comp.bits else None


# ====================================================================== builder
class CbomBuilder:
    def __init__(self, catalog: Catalog):
        self.cat = catalog
        self.components: dict[str, dict] = {}
        self.services: dict[str, dict] = {}
        self.deps: dict[str, dict[str, set]] = {}
        self._meta: dict[str, dict] = {}            # bom-ref -> aggregated facts for properties
        self._occ: dict[str, dict] = {}             # bom-ref -> {(location, line, ctx): occurrence}
        self._protocols: dict[str, list[Finding]] = {}
        self.nodes: set[str] = set()                # assets: what the scan target is made of
        self._x509_names = {norm(v): v for v in catalog.x509_oids.values()}
        self._x509_oid = {norm(v): k for k, v in catalog.x509_oids.items()}

    # ------------------------------------------------------------------ bookkeeping
    def _dep(self, ref: str, depends: list[str] = (), provides: list[str] = ()) -> None:
        d = self.deps.setdefault(ref, {"dependsOn": set(), "provides": set()})
        d["dependsOn"] |= {x for x in depends if x != ref}
        d["provides"] |= {x for x in provides if x != ref}

    def _note(self, ref: str, f: Finding, tier: Tier | None = None, hndl: bool | None = None,
              flags: set | None = None, replacement: str | None = None, standard: str | None = None) -> None:
        m = self._meta.setdefault(ref, {"tier": None, "hndl": False, "flags": set(), "replacements": [],
                                        "standards": [], "findings": set(), "assets": set(), "confidence": 1.0})
        c = f.classification
        tier = tier or (c.tier if c else None)
        if tier and (m["tier"] is None or tier.severity > m["tier"].severity):
            m["tier"] = tier
        m["hndl"] |= bool(c.hndl if hndl is None and c else hndl)
        m["flags"] |= set(flags if flags is not None else (c.flags if c else ()))
        if replacement and replacement not in m["replacements"]:
            m["replacements"].append(replacement)
        if standard and standard not in m["standards"]:
            m["standards"].append(standard)
        m["findings"].add(f.id)
        m["assets"].add(f.asset)
        m["confidence"] = min(m["confidence"], f.confidence)
        location, line, ctx = split_location(f.location)
        occ = self._occ.setdefault(ref, {}).setdefault((location, line, ctx, f.asset),
                                                        {"location": location, "line": line, "ctx": ctx,
                                                         "asset": f.asset, "ids": [], "evidence": f.evidence[:120]})
        if f.id not in occ["ids"]:
            occ["ids"].append(f.id)

    # ------------------------------------------------------------------ asset nodes
    def node(self, f: Finding) -> str:
        """The thing that uses the crypto: a file (code / config / key file) or a service (endpoint).
        A cloud KMS key or ACM certificate is its own asset."""
        if f.source == "cloud" and "key" in f.details:
            ref = self.key_ref(f.details["key"])
        elif f.source == "cloud" and "cert" in f.details:
            ref = f"crypto/certificate/{f.details['cert']}"
        elif f.source in ("pcap", "cloud") or (f.source == "config" and f.library in ("nginx", "apache")):
            ref = f"service/{f.asset}"
            self.services.setdefault(ref, {"bom-ref": ref, "name": f.asset})
            self._note(ref, f)
        else:
            ref = f"file/{f.asset}"
            self.components.setdefault(ref, {"type": "file", "bom-ref": ref, "name": f.asset})
            self._note(ref, f)
        self.nodes.add(ref)
        return ref

    # ------------------------------------------------------------------ algorithms
    def algorithm(self, comp: ComponentResult, f: Finding) -> str:
        ref, name = f"crypto/algorithm/{comp.id}", comp.name
        if comp.catalog_key and self.cat.entry(comp.catalog_key).get("primitive_by_role"):
            ref, name = f"{ref}/{comp.primitive}", f"{comp.name} ({comp.primitive})"   # RSA as pke vs as signature
        if ref not in self.components:
            props = {"primitive": comp.primitive if comp.primitive in PRIMITIVES else "unknown"}
            if _param_set(comp):
                props["parameterSetIdentifier"] = _param_set(comp)
            if comp.catalog_key in CURVES:
                props["curve"] = CURVES[comp.catalog_key]
            if comp.mode:
                m = comp.mode.split("_")[0].replace("ccm8", "ccm")
                props["mode"] = m if m in MODES else "other"
            if comp.classical_level is not None:
                props["classicalSecurityLevel"] = int(comp.classical_level)
            if comp.nist_quantum_level is not None:
                props["nistQuantumSecurityLevel"] = int(comp.nist_quantum_level)
            crypto = {"assetType": "algorithm", "algorithmProperties": props}
            if _oid(comp):
                crypto["oid"] = _oid(comp)
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                                    "cryptoProperties": crypto}
        fns = self.components[ref]["cryptoProperties"]["algorithmProperties"].setdefault("cryptoFunctions", [])
        for fn in _functions(self.components[ref]["cryptoProperties"]["algorithmProperties"]["primitive"], comp.role):
            if fn not in fns:
                fns.append(fn)
        self._note(ref, f, tier=comp.tier, hndl=comp.hndl, flags=comp.flags,
                   replacement=comp.replacement if comp.tier is not Tier.SAFE else None, standard=comp.standard)
        return ref

    def algorithms(self, f: Finding, split_suites: bool = False) -> list[str]:
        """Refs of what this finding uses. A composite name becomes its own algorithm (unless it is a
        TLS cipher suite and `split_suites`: then the parts are returned for the protocol component)."""
        c = f.classification
        if c is None or f.flags & PSEUDO_FLAGS:
            return []
        comps = [x for x in c.components if x.catalog_key != "PLAINTEXT" and x.kind != "none"
                 and not (x.catalog_key is None and x.name.startswith(("tls-", "ssh-", "unknown-", "encrypted-")))]
        refs = [self.algorithm(x, f) for x in comps]
        if len(refs) <= 1 or split_suites:
            return refs
        return [self.composite(f, comps, refs)]

    def composite(self, f: Finding, comps: list[ComponentResult], parts: list[str]) -> str:
        raw = re.sub(r"@[\w.-]+$", "", f.algorithm.strip())
        m = re.match(r"^(ecdsa|rsa|dsa)[_-]?with[_-]?(sha\d+)$", raw, re.I)        # ACM ECDSA_WITH_SHA256
        if m:
            raw = f"{m.group(2).upper()}with{m.group(1).upper()}"
        name = self._x509_names.get(norm(raw), raw)          # SHA256WITHRSA (ACM) == SHA256withRSA (X.509)
        ref = f"crypto/algorithm/{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}"
        if ref not in self.components:
            prims = [x.primitive for x in comps]
            primitive = next((p for p in ("kem", "signature", "key-agree", "ae", "pke", "kdf", "mac")
                              if p in prims), prims[0])
            props = {"primitive": primitive if primitive in PRIMITIVES else "unknown"}
            nq = [x.nist_quantum_level for x in comps if x.nist_quantum_level is not None]
            cl = [x.classical_level for x in comps if x.classical_level is not None]
            if nq:
                props["nistQuantumSecurityLevel"] = int(min(nq))
            if cl:
                props["classicalSecurityLevel"] = int(min(cl))
            props["cryptoFunctions"] = _functions(primitive, f.usage) or ["other"]
            crypto = {"assetType": "algorithm", "algorithmProperties": props}
            if norm(raw) in self._x509_oid:
                crypto["oid"] = self._x509_oid[norm(raw)]
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                                    "cryptoProperties": crypto}
        c = f.classification
        self._note(ref, f, tier=c.tier, hndl=c.hndl, flags=c.flags)
        for x in comps:                                      # what to migrate each broken part to
            if x.tier is not Tier.SAFE and x.replacement:
                self._note(ref, f, replacement=x.replacement, standard=x.standard)
        self._dep(ref, parts)
        return ref

    # ------------------------------------------------------------------ certificates and keys
    def certificate(self, f: Finding) -> str:
        d = f.details
        ref = f"crypto/certificate/{d['cert']}"
        if ref not in self.components:
            cn = re.search(r"CN=([^,]+)", d.get("subject", ""))
            props = {"certificateFormat": "X.509"}
            for key, name in (("subject", "subjectName"), ("issuer", "issuerName")):
                if d.get(key):
                    props[name] = d[key]
            for key, name in (("not_before", "notValidBefore"), ("not_after", "notValidAfter")):
                if _iso(d.get(key)):
                    props[name] = _iso(d[key])
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref,
                                    "name": cn.group(1) if cn else f.asset,
                                    "cryptoProperties": {"assetType": "certificate", "certificateProperties": props}}
        props = self.components[ref]["cryptoProperties"]["certificateProperties"]
        algs = self.algorithms(f)
        if d.get("cert_part") == "signature" and algs:
            props["signatureAlgorithmRef"] = algs[0]
            self._dep(ref, algs)
        elif algs:
            key = self.key(f"{d['cert']}/public-key", "public-key", algs[0], f, name=f"public key of {self.components[ref]['name']}")
            props["subjectPublicKeyRef"] = key
            self._dep(ref, [key])
        self._note(ref, f)
        return ref

    def key_ref(self, identity: str) -> str:
        return f"crypto/key/{identity}"

    def key(self, identity: str, key_type: str, alg_ref: str | None, f: Finding, name: str | None = None) -> str:
        ref = self.key_ref(identity)
        if ref not in self.components:
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": name or f.asset,
                                    "cryptoProperties": {"assetType": "related-crypto-material",
                                                         "relatedCryptoMaterialProperties": {"type": key_type}}}
        props = self.components[ref]["cryptoProperties"]["relatedCryptoMaterialProperties"]
        if alg_ref and "algorithmRef" not in props:
            props["algorithmRef"] = alg_ref
            self._dep(ref, [alg_ref])
        bits = f.key_size or next((x.bits for x in (f.classification.components if f.classification else [])
                                   if x.bits and x.kind in ("asymmetric", "symmetric", "pqc")), None)
        if bits and "size" not in props:
            props["size"] = int(bits)
        d = f.details
        if d.get("key") == identity:
            props["id"] = identity
            if d.get("key_state"):
                props["state"] = d["key_state"]
            for key, name_ in (("created", "creationDate"), ("expires", "expirationDate")):
                if _iso(d.get(key)):
                    props[name_] = _iso(d[key])
        self._note(ref, f)
        return ref

    def key_finding(self, f: Finding) -> str:
        d = f.details
        algs = self.algorithms(f)
        if d.get("key_part") == "algorithm":                     # a KMS key's allowed algorithm
            ref = self.key_ref(d["key"])
            self.components.setdefault(ref, {"type": "cryptographic-asset", "bom-ref": ref, "name": f.asset,
                                             "cryptoProperties": {"assetType": "related-crypto-material",
                                                                  "relatedCryptoMaterialProperties": {"type": "key"}}})
            self._dep(ref, algs)
            self._note(ref, f)
            return ref
        return self.key(d["key"], d.get("key_type", "key"), algs[0] if algs else None, f,
                        name=f.asset if f.source == "cloud" else f"{d.get('key_type', 'key')} {d['key']}")

    # ------------------------------------------------------------------ libraries
    def library(self, f: Finding) -> str | None:
        """Declared library (manifest) or the platform API a code finding uses."""
        if f.usage is Usage.LIBRARY or f.purl:
            ref = f"lib/{f.purl}" if f.purl else f"lib/{f.library}"
            if ref not in self.components:
                eco, name, version = parse_purl(f.purl) if f.purl else ("", f.library, None)
                group, _, short = name.rpartition(":") if eco == "maven" else ("", "", name)
                comp = {"type": "library", "bom-ref": ref, "name": short or name}
                if group:
                    comp["group"] = group
                if version:
                    comp["version"] = version
                if f.purl:
                    comp["purl"] = f.purl
                self.components[ref] = comp
            if f.usage is Usage.LIBRARY:
                c = f.classification
                self._note(ref, f, tier=Tier.INFO, flags=c.flags if c else set())
                for r in (c.replacements if c else []):
                    self._note(ref, f, replacement=r)
                if f.version and "version" not in self.components[ref]:
                    self._meta[ref]["declared"] = f.version
            return ref
        lib = f.library
        if not lib or lib == "unknown" or f.source != "code":
            return None
        if lib in PY_STDLIB:
            key = "python-stdlib"
        elif lib.startswith(("java.", "javax.")):
            key = "java-jca"
        elif "/" in lib and "." not in lib.split("/", 1)[0] or lib in ("crypto",):
            key = "go-stdlib"
        else:
            key = lib
        ref = f"lib/{key}"
        self.components.setdefault(ref, {"type": "library", "bom-ref": ref, "name": LIB_PLATFORMS.get(key, key)})
        return ref

    # ------------------------------------------------------------------ protocols
    def protocol(self, asset: str, findings: list[Finding]) -> str | None:
        kind = findings[0].details.get("protocol")
        suites, refs = [], []
        version = ""
        for f in findings:
            d = f.details
            version = version or d.get("tls_version") or d.get("tls_versions", "")
            if kind == "tls" and f.usage is Usage.PROTOCOL:
                if f.flags & PSEUDO_FLAGS:
                    continue
                algs = self.algorithms(f, split_suites=True)
                entry = {"name": f.algorithm, "algorithms": sorted(set(algs))}
                if d.get("suite_id"):
                    h = d["suite_id"][2:].rjust(4, "0")
                    entry["identifiers"] = [f"0x{h[:2]}", f"0x{h[2:]}"]
                if entry not in suites:
                    suites.append(entry)
            else:
                for r in self.algorithms(f):
                    if r not in refs:
                        refs.append(r)
        if not suites and not refs:
            return None
        if kind == "ssh":
            version = "2.0"
        sig = json.dumps([kind, version, sorted(s["name"] for s in suites), sorted(refs)])
        ref = f"crypto/protocol/{kind}-{version.replace(',', '_') or 'unknown'}-{hashlib.sha256(sig.encode()).hexdigest()[:10]}"
        if ref not in self.components:
            props = {"type": kind if kind in ("tls", "ssh") else "other"}
            if version:
                props["version"] = version
            if suites:
                props["cipherSuites"] = sorted(suites, key=lambda s: s["name"])
            if refs:
                props["cryptoRefArray"] = sorted(refs)
            offered = any("offered" in f.flags for f in findings)
            label = kind.upper() + (f" {version.replace(',', '/')}" if version else "")
            parts = [s["name"] for s in suites[:1]] + [self.components[r]["name"] for r in refs[:2]]
            more = len(suites) + len(refs) - len(parts)
            name = f"{label}: {' + '.join(parts)}" + (f" (+{more} more)" if more > 0 else "")
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                                    "cryptoProperties": {"assetType": "protocol", "protocolProperties": props}}
            self._meta.setdefault(ref, {"tier": None, "hndl": False, "flags": set(), "replacements": [],
                                        "standards": [], "findings": set(), "assets": set(), "confidence": 1.0})
            self._meta[ref]["mode"] = "offered (configuration)" if offered else "negotiated (observed)"
        for f in findings:
            self._note(ref, f)
        self._dep(ref, [r for s in suites for r in s["algorithms"]] + refs)
        return ref

    # ------------------------------------------------------------------ main
    def add(self, findings: list[Finding]) -> None:
        for f in findings:
            if f.classification is None:
                continue
            node = self.node(f)
            if f.usage is Usage.LIBRARY:
                lib = self.library(f)
                self._dep(node, [lib])
                continue
            d = f.details
            if "cert" in d:
                refs = [self.certificate(f)]
            elif "key" in d:
                refs = [self.key_finding(f)]
            elif d.get("protocol") in ("tls", "ssh"):
                self._protocols.setdefault(f.asset, []).append(f)
                continue
            else:
                refs = self.algorithms(f)
            if node not in refs:
                self._dep(node, refs)
            lib = self.library(f)
            if lib:
                self._dep(node, [lib])
                self._dep(lib, provides=refs)
        for asset, fs in self._protocols.items():
            by_kind: dict[str, list[Finding]] = {}
            for f in fs:
                by_kind.setdefault(f.details["protocol"], []).append(f)
            for group in by_kind.values():
                ref = self.protocol(asset, group)
                if ref:
                    self._dep(self.node(group[0]), [ref])

    # ------------------------------------------------------------------ output
    def _properties(self, ref: str) -> list[dict]:
        m = self._meta.get(ref)
        if not m:
            return []
        out = []
        if m["tier"]:
            out.append({"name": "quantumtrace:tier", "value": m["tier"].value})
        if m["tier"] is Tier.CRITICAL:
            out.append({"name": "quantumtrace:hndl", "value": str(m["hndl"]).lower()})
        if "classically-broken" in m["flags"] or "weak-key-size" in m["flags"]:
            out.append({"name": "quantumtrace:classicallyBroken", "value": "true"})
        if m.get("mode"):
            out.append({"name": "quantumtrace:observation", "value": m["mode"]})
        if m.get("declared"):
            out.append({"name": "quantumtrace:declaredVersion", "value": m["declared"]})
        for r in m["replacements"]:
            out.append({"name": "quantumtrace:pqcReplacement", "value": r})
        for s in m["standards"]:
            out.append({"name": "quantumtrace:standard", "value": s})
            for key, (sref, _, _) in STANDARDS.items():
                if key in s:
                    out.append({"name": "quantumtrace:standardRef", "value": sref})
        for flag in sorted(m["flags"]):
            out.append({"name": "quantumtrace:flag", "value": flag})
        out.append({"name": "quantumtrace:findings", "value": str(len(m["findings"]))})
        out.append({"name": "quantumtrace:assets", "value": str(len(m["assets"]))})
        if m["confidence"] < 1.0:
            out.append({"name": "quantumtrace:minConfidence", "value": f"{m['confidence']:.2f}"})
        return out

    @staticmethod
    def _occurrence(o: dict) -> dict:
        """One place (file + line / JSON path / PCAP stream) and the finding ids seen there."""
        ids = o["ids"]
        found = f"finding {ids[0]}" if len(ids) == 1 else f"findings {', '.join(ids)}"
        out = {"location": o["location"]}
        if o["line"]:
            out["line"] = o["line"]
        out["additionalContext"] = "; ".join(x for x in (o["ctx"], f"asset {o['asset']}", found, o["evidence"]) if x)
        return out

    def components_out(self) -> list[dict]:
        out = []
        for ref in sorted(self.components):
            c = dict(self.components[ref])
            occ = self._occ.get(ref)
            if occ and c["type"] == "cryptographic-asset":
                c["evidence"] = {"occurrences": [self._occurrence(o) for o in sorted(
                    occ.values(), key=lambda o: (o["location"], o["line"] or 0, o["ctx"], o["asset"]))]}
            props = self._properties(ref)
            if props:
                c["properties"] = props
            out.append(c)
        return out

    def services_out(self) -> list[dict]:
        out = []
        for ref in sorted(self.services):
            s = dict(self.services[ref])
            props = self._properties(ref)
            if props:
                s["properties"] = props
            out.append(s)
        return out

    def dependencies_out(self, root: str) -> list[dict]:
        out = [{"ref": root, "dependsOn": sorted(self.nodes)}]
        for ref in sorted(self.deps):
            d = self.deps[ref]
            entry = {"ref": ref}
            if d["dependsOn"]:
                entry["dependsOn"] = sorted(d["dependsOn"])
            if d["provides"]:
                entry["provides"] = sorted(d["provides"])
            out.append(entry)
        return out


def build_cbom(findings: list[Finding], score: RiskScore | None = None, target: str = "scan target",
               catalog: Catalog | None = None, serial: str | None = None, timestamp: datetime | None = None) -> dict:
    cat = catalog or load_catalog()
    b = CbomBuilder(cat)
    b.add(findings)
    root = "quantumtrace/target"
    metadata = {
        "timestamp": (timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {"components": [{"type": "application", "name": "QuantumTrace", "version": __version__,
                                  "description": "Post-quantum cryptography discovery (JunctionX Lisbon 2026)"}]},
        "component": {"type": "application", "bom-ref": root, "name": target},
    }
    if score is not None:
        props = [{"name": "quantumtrace:quantumRiskScore", "value": str(score.score)}]
        props += [{"name": f"quantumtrace:riskScore:{k}", "value": str(v)} for k, v in score.by_source.items()]
        if score.pqc_readiness is not None:
            props.append({"name": "quantumtrace:pqcReadiness:network", "value": f"{score.pqc_readiness:.4f}"})
        metadata["properties"] = props
    bom = {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": metadata,
        "components": b.components_out(),
    }
    services = b.services_out()
    if services:
        bom["services"] = services
    bom["dependencies"] = b.dependencies_out(root)
    bom["definitions"] = {"standards": [
        {"bom-ref": ref, "name": f"NIST {key}", "version": "final, 2024-08-13", "description": desc, "owner": "NIST",
         "externalReferences": [{"type": "documentation", "url": f"https://csrc.nist.gov/pubs/fips/{num}/final"},
                                {"type": "documentation", "url": f"https://doi.org/10.6028/NIST.FIPS.{num}"}]}
        for key, (ref, desc, num) in STANDARDS.items()]}
    return bom


# ====================================================================== validation
def integrity_errors(bom: dict) -> list[str]:
    """What the JSON schema cannot check: bom-refs unique, every reference points to something."""
    errors, refs = [], []
    for c in bom.get("components", []) + bom.get("services", []) + [bom["metadata"].get("component", {})]:
        if "bom-ref" in c:
            refs.append(c["bom-ref"])
    refs += [s["bom-ref"] for s in bom.get("definitions", {}).get("standards", [])]
    dup = {r for r in refs if refs.count(r) > 1}
    if dup:
        errors.append(f"duplicate bom-ref: {sorted(dup)[:5]}")
    known = set(refs)

    def check(ref, where):
        if ref not in known:
            errors.append(f"{where} -> unknown ref {ref!r}")

    for c in bom.get("components", []):
        cp = c.get("cryptoProperties", {})
        for key in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
            if key in cp.get("certificateProperties", {}):
                check(cp["certificateProperties"][key], c["bom-ref"])
        if "algorithmRef" in cp.get("relatedCryptoMaterialProperties", {}):
            check(cp["relatedCryptoMaterialProperties"]["algorithmRef"], c["bom-ref"])
        pp = cp.get("protocolProperties", {})
        for s in pp.get("cipherSuites", []):
            for r in s.get("algorithms", []):
                check(r, c["bom-ref"])
        for r in pp.get("cryptoRefArray", []):
            check(r, c["bom-ref"])
    for d in bom.get("dependencies", []):
        check(d["ref"], "dependencies")
        for r in d.get("dependsOn", []) + d.get("provides", []):
            check(r, f"dependencies[{d['ref']}]")
    return errors


def validate(bom: dict) -> tuple[bool | None, list[str]]:
    """-> (valid?, messages). valid is None when the official schema validator is not installed."""
    errors = integrity_errors(bom)
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return (None if not errors else False), errors + ["cyclonedx-python-lib not installed: schema not checked"]
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    if err is not None:
        errors.insert(0, f"schema: {str(err).splitlines()[0]}")
    return not errors, errors
