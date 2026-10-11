"""Cloud posture parser.

Understands three AWS export formats (the ones in the starter kit) and falls back
to a generic JSON walker for anything else (GCP, Azure, Terraform state, ...):

    kms_key_inventory.json        {"Keys": [...]}           kms:ListKeys + DescribeKey
    load_balancer_listeners.json  {"LoadBalancers": [...]}  elbv2:DescribeLoadBalancers + DescribeListeners
    acm_certificates.json         {"Certificates": [...]}   acm:DescribeCertificate
    anything else                 generic walker: crypto-looking keys with recognisable values

Parsers only REPORT what they see (raw names + facts as flags); the classifier
decides tiers later. Every finding carries a JSON path as evidence location.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..catalog import Catalog, load_catalog
from ..classify import classify_name
from ..models import Finding, Tier, Usage

KMS_USAGE = {"SIGN_VERIFY": Usage.SIGNATURE, "ENCRYPT_DECRYPT": Usage.ENCRYPTION,
             "KEY_AGREEMENT": Usage.KEY_EXCHANGE, "GENERATE_VERIFY_MAC": Usage.MAC}
# AWS KeyState -> CycloneDX relatedCryptoMaterial state
KMS_STATE = {"Enabled": "active", "Disabled": "suspended", "PendingDeletion": "deactivated",
             "PendingReplicaDeletion": "deactivated", "PendingImport": "pre-activation", "Unavailable": "suspended",
             "Creating": "pre-activation", "Updating": "active"}
# keys whose loss would hurt for years: roots of trust, code / firmware signing
LONG_LIVED = re.compile(r"\b(root|certificate authority|ca|code-?sign\w*|firmware|release)\b", re.I)
EXPIRING_SOON = timedelta(days=30)


# =================================================================== entry points
def detect(doc) -> str:
    """Which export format is this JSON document?"""
    if isinstance(doc, dict):
        if isinstance(doc.get("Keys"), list) and any("KeySpec" in k for k in doc["Keys"] if isinstance(k, dict)):
            return "aws-kms"
        if isinstance(doc.get("LoadBalancers"), list):
            return "aws-elb"
        if isinstance(doc.get("Certificates"), list) and any(
                "KeyAlgorithm" in c for c in doc["Certificates"] if isinstance(c, dict)):
            return "aws-acm"
    return "generic"


def parse_cloud_files(paths: list[Path], root: Path | None = None, now: datetime | None = None,
                      catalog: Catalog | None = None) -> list[Finding]:
    """Parse several JSON files together (so certificates can be joined to listeners)."""
    cat = catalog or load_catalog()
    now = now or datetime.now(timezone.utc)
    docs = []
    for p in paths:
        try:
            doc = json.loads(Path(p).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue                                   # not JSON: not ours
        name = str(Path(p).relative_to(root)) if root else Path(p).name
        docs.append((name, doc, detect(doc)))

    findings: list[Finding] = []
    for name, doc, kind in docs:
        if kind == "aws-kms":
            findings += parse_kms(doc, name, now)
        elif kind == "aws-acm":
            findings += parse_acm(doc, name, now)
        elif kind == "aws-elb":
            findings += parse_elb(doc, name, cat)
        else:
            findings += parse_generic(doc, name, cat)
    _join_certificates_to_listeners(findings)
    return findings


def _f(**kw) -> Finding:
    return Finding(source="cloud", **kw)


# =================================================================== AWS KMS
def parse_kms(doc: dict, name: str, now: datetime) -> list[Finding]:
    out = []
    for i, k in enumerate(doc["Keys"]):
        loc = f"{name}:$.Keys[{i}]"
        asset = k.get("AliasName") or k.get("KeyArn") or k.get("KeyId", f"key[{i}]")
        usage = KMS_USAGE.get(k.get("KeyUsage"), Usage.UNKNOWN)

        flags = set()
        state = k.get("KeyState", "")
        if state == "PendingDeletion":
            flags.add("pending-deletion")
        elif state in ("Disabled", "Unavailable", "PendingImport"):
            flags.add(state.lower().replace("pendingimport", "pending-import"))
        if k.get("KeyRotationStatus") == "DISABLED":
            flags.add("rotation-disabled")
        if k.get("Origin") == "EXTERNAL":
            flags.add("imported-key-material")
        if k.get("Origin") == "AWS_CLOUDHSM":
            flags.add("hsm-backed")
        if k.get("MultiRegion"):
            flags.add("multi-region")
        if LONG_LIVED.search(f"{k.get('AliasName', '')} {k.get('Description', '')}"):
            flags.add("long-lived")
        if _expired(k.get("ValidTo"), now):
            flags.add("expired")

        context = f"KMS {k.get('KeyUsage', '?')} key: {k.get('Description', '')}".strip()
        if k.get("DeletionDate"):
            context += f" (scheduled deletion {k['DeletionDate'][:10]})"
        related = [k["KeyArn"]] if k.get("KeyArn") else []

        spec = k.get("KeySpec") or k.get("CustomerMasterKeySpec")
        key = {"key": k.get("KeyArn") or k.get("KeyId") or asset}
        if spec:
            details = {**key, "key_type": "secret-key" if spec.upper().startswith(("SYMMETRIC", "HMAC")) else "private-key"}
            if k.get("KeyState") in KMS_STATE:
                details["key_state"] = KMS_STATE[k["KeyState"]]
            for field_, detail in (("CreationDate", "created"), ("ValidTo", "expires"), ("DeletionDate", "deletion")):
                if k.get(field_):
                    details[detail] = str(k[field_])
            out.append(_f(location=loc, algorithm=spec, usage=usage, asset=asset, context=context,
                          evidence=f"KeySpec={spec} KeyUsage={k.get('KeyUsage')}", flags=set(flags),
                          related=list(related), details=details))
        for field in ("SigningAlgorithms", "EncryptionAlgorithms", "KeyAgreementAlgorithms", "MacAlgorithms"):
            for j, alg in enumerate(k.get(field, [])):
                if alg == spec:
                    continue                           # SYMMETRIC_DEFAULT twice says nothing new
                out.append(_f(location=f"{loc}.{field}[{j}]", algorithm=alg, usage=usage, asset=asset,
                              context=context, evidence=f"{field}[{j}]={alg}", flags=set(flags),
                              related=list(related), details={**key, "key_part": "algorithm"}))
    return out


# =================================================================== AWS ACM
def parse_acm(doc: dict, name: str, now: datetime) -> list[Finding]:
    out = []
    for i, c in enumerate(doc["Certificates"]):
        loc = f"{name}:$.Certificates[{i}]"
        asset = c.get("DomainName") or c.get("CertificateArn", f"certificate[{i}]")
        flags = set()
        if _expired(c.get("NotAfter"), now):
            flags.add("expired")
        elif _expired(c.get("NotAfter"), now + EXPIRING_SOON):
            flags.add("expiring-soon")
        if c.get("Type") == "IMPORTED":
            flags.add("imported")
        if c.get("RenewalEligibility") == "INELIGIBLE":
            flags.add("renewal-ineligible")
        if c.get("Status") not in (None, "ISSUED"):
            flags.add(f"status-{c['Status'].lower()}")
        related = [c["CertificateArn"]] if c.get("CertificateArn") else []
        related += list(c.get("InUseBy", []))
        context = f"ACM certificate {asset}, valid until {str(c.get('NotAfter', '?'))[:10]}"
        cert = {"cert": c.get("CertificateArn") or f"{name}:{loc}", "subject": f"CN={c['DomainName']}" if c.get("DomainName") else ""}
        for field_, name_ in (("NotBefore", "not_before"), ("NotAfter", "not_after")):
            if c.get(field_):
                cert[name_] = str(c[field_])
        cert = {k: v for k, v in cert.items() if v}
        for field, part in (("KeyAlgorithm", "public-key"), ("SignatureAlgorithm", "signature")):
            if c.get(field):
                out.append(_f(location=f"{loc}.{field}", algorithm=c[field], usage=Usage.CERTIFICATE,
                              asset=asset, context=context, evidence=f"{field}={c[field]}",
                              flags=set(flags), related=list(related), details={**cert, "cert_part": part}))
    return out


# =================================================================== AWS ELB listeners
def parse_elb(doc: dict, name: str, cat: Catalog) -> list[Finding]:
    out = []
    for i, lb in enumerate(doc["LoadBalancers"]):
        lb_name = lb.get("LoadBalancerName", f"lb[{i}]")
        base = {"internet-facing"} if lb.get("Scheme") == "internet-facing" else set()
        for j, lis in enumerate(lb.get("Listeners", [])):
            loc = f"{name}:$.LoadBalancers[{i}].Listeners[{j}]"
            asset = f"{lb_name}:{lis.get('Port', '?')}"
            proto = str(lis.get("Protocol", "")).upper()
            certs = [c["CertificateArn"] for c in lis.get("Certificates", []) if c.get("CertificateArn")]
            related = ([lis["ListenerArn"]] if lis.get("ListenerArn") else []) + certs
            common = dict(location=loc, asset=asset, related=related)

            if proto in ("HTTPS", "TLS"):
                out += _expand_policy(lis.get("SslPolicy"), cat, base, common, proto)
            else:                                      # HTTP / TCP / UDP: no TLS at the load balancer
                flags = set(base)
                redirect = any(a.get("Type") == "redirect" and
                               str(a.get("RedirectConfig", {}).get("Protocol", "")).upper() == "HTTPS"
                               for a in lis.get("DefaultActions", []))
                if redirect:
                    flags.add("redirect-to-https")
                if proto in ("TCP", "UDP", "TCP_UDP"):
                    flags.add("tls-not-terminated-here")    # traffic may still be TLS end-to-end
                out.append(_f(algorithm="plaintext", usage=Usage.PROTOCOL, flags=flags,
                              details={"protocol": proto.lower() or "tcp"},
                              confidence=0.5 if proto != "HTTP" else 1.0,
                              context=f"{proto} listener" + (" (redirects to HTTPS)" if redirect else ""),
                              evidence=f"Protocol={proto}", **common))
    return out


def _expand_policy(policy: str | None, cat: Catalog, base: set, common: dict, proto: str) -> list[Finding]:
    """One SslPolicy name -> one finding per cipher suite / key-exchange group it OFFERS."""
    pol = cat.aws_elb_policies.get(policy or "")
    if pol is None:                                    # unknown policy: say so, guess from the name
        out = [_f(algorithm=policy or "missing-ssl-policy", usage=Usage.PROTOCOL,
                  flags=base | {"unknown-policy"}, confidence=0.3,
                  context=f"{proto} listener with an SslPolicy not in the catalog",
                  evidence=f"SslPolicy={policy}", details={"protocol": "tls"}, **common)]
        if policy and "-PQ-" in policy:
            out.append(_f(algorithm="X25519MLKEM768", usage=Usage.KEY_EXCHANGE, flags=base | {"inferred-from-name"},
                          details={"protocol": "tls"},
                          confidence=0.5, context=f"post-quantum group inferred from policy name {policy}",
                          evidence=f"SslPolicy={policy}", **common))
        return out

    versions = pol.get("tls_versions", [])
    tls = {"protocol": "tls", "tls_versions": ",".join(versions)}
    flags = set(base) | {"offered"} | {f"tls{v}-enabled" for v in versions if v in ("1.0", "1.1")}
    confidence = 1.0 if pol.get("verified", True) else 0.7
    if not pol.get("verified", True):
        flags.add("policy-data-unverified")
    ev = f"SslPolicy={policy}"
    out = [_f(algorithm=c, usage=Usage.PROTOCOL, flags=set(flags), confidence=confidence,
              context=f"cipher suite offered by {policy}", evidence=ev, details=dict(tls), **common)
           for c in pol.get("ciphers", [])]

    if "1.3" in versions:                              # TLS 1.3 suites don't name the key exchange
        kex_flags = set(flags)
        if pol.get("pq_groups"):
            kex_flags.add("downgrade-risk")            # classical fallback for clients without ML-KEM
        out.append(_f(algorithm="ECDHE", usage=Usage.KEY_EXCHANGE, flags=kex_flags, confidence=confidence,
                      details=dict(tls),
                      context=f"classical (EC)DHE key exchange offered by {policy}"
                              + (" as fallback for non-PQ clients" if pol.get("pq_groups") else ""),
                      evidence=ev, **common))
    for g in pol.get("pq_groups", []):
        out.append(_f(algorithm=g, usage=Usage.KEY_EXCHANGE, flags=set(flags), confidence=confidence,
                      details=dict(tls),
                      context=f"hybrid post-quantum group offered by {policy}", evidence=ev, **common))
    return out


def _join_certificates_to_listeners(findings: list[Finding]) -> None:
    """Certificate findings learn which listeners present them, and vice versa (traceability)."""
    listeners_by_cert: dict[str, set[str]] = {}
    for f in findings:
        if f.usage is not Usage.CERTIFICATE:
            for arn in f.related:
                if ":certificate/" in arn:
                    listeners_by_cert.setdefault(arn, set()).add(f.asset)
    for f in findings:
        if f.usage is Usage.CERTIFICATE:
            for arn in list(f.related):
                for listener in sorted(listeners_by_cert.get(arn, ())):
                    if listener not in f.related:
                        f.related.append(listener)


# =================================================================== generic JSON
GENERIC_KEY = re.compile(r"(algorithm|algo$|^alg$|^enc$|keyspec|key_?spec|keytype|key_?type|^kty$|^crv$|curve|cipher|"
                         r"sslpolicy|ssl_?policy|protocols?$|signature|digest|hash_?alg)", re.I)
SIZE_KEYS = ("keySize", "key_size", "KeySize", "keyLength", "key_length", "bits", "size")


# what the key is FOR, from fields next to (or above) the algorithm: GCP purpose, JWK key_ops / use,
# AWS KeyUsage. First match wins; values are compared upper-case without separators.
USAGE_FIELDS = ("purpose", "keyOps", "key_ops", "keyops", "use", "KeyUsage", "keyUsage")
USAGE_VALUES = [
    (Usage.SIGNATURE, ("SIGN", "VERIFY", "SIG")),
    (Usage.KEY_EXCHANGE, ("DERIVEKEY", "DERIVEBITS", "KEYAGREEMENT", "KEYENCAPSULATION")),
    (Usage.ENCRYPTION, ("ENCRYPT", "DECRYPT", "WRAPKEY", "UNWRAPKEY", "ENC")),
    (Usage.MAC, ("MAC",)),
]
ID_FIELDS = ("name", "Name", "id", "Id", "arn", "Arn", "kid", "alias", "Alias", "KeyId", "keyId")


def parse_generic(doc, name: str, cat: Catalog) -> list[Finding]:
    """Walk any JSON; report string values under crypto-looking keys that the catalog recognises."""
    out = []
    for path, key, value, ancestors in _walk(doc, "$"):
        parent = ancestors[-1] if ancestors else None
        if not (isinstance(value, str) and GENERIC_KEY.search(str(key))):
            continue
        if value in cat.aws_elb_policies:              # an ELB policy name inside some other export
            out += _expand_policy(value, cat, set(), dict(location=f"{name}:{path}", asset=f"{name}:{path}",
                                                          related=[]), "TLS")
            continue
        c = classify_name(value, catalog=cat)
        if all(comp.catalog_key is None for comp in c.components):
            continue                                   # not a crypto name we know: stay quiet
        k = str(key).lower()
        usage = (Usage.SIGNATURE if "sign" in k else Usage.ENCRYPTION if "encrypt" in k or "decrypt" in k
                 else _usage_from(ancestors))
        size = next((parent[s] for s in SIZE_KEYS if isinstance(parent, dict) and isinstance(parent.get(s), int)), None)
        out.append(_f(location=f"{name}:{path}", algorithm=value, usage=usage, key_size=size,
                      asset=_asset_name(ancestors, name, path), evidence=f"{key}={value}",
                      context=f"generic JSON field '{key}'", confidence=0.6))
    return out


def _walk(obj, path, ancestors=(), key=None):
    """Yield (json path, key, scalar value, enclosing objects from the outermost to the nearest)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}", (*ancestors, obj), k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]", ancestors, key)   # list items inherit the key name
    else:
        yield path, key, obj, ancestors


def _usage_from(ancestors) -> Usage:
    for obj in reversed(ancestors):                    # nearest object first
        for field_name in USAGE_FIELDS:
            v = obj.get(field_name)
            vals = v if isinstance(v, list) else [v] if isinstance(v, str) else []
            norm_vals = [re.sub(r"[^A-Z]", "", str(x).upper()) for x in vals]
            for usage, words in USAGE_VALUES:
                if any(nv == w or nv.startswith(("ASYMMETRIC" + w, w)) for nv in norm_vals for w in words):
                    return usage
    return Usage.UNKNOWN


def _asset_name(ancestors, name: str, path: str) -> str:
    """The nearest enclosing object that has an identity (GCP key name, JWK kid, ARN ...)."""
    for obj in reversed(ancestors):
        for k in ID_FIELDS:
            if isinstance(obj.get(k), str) and obj[k]:
                return obj[k]
    return f"{name}:{path.rsplit('.', 1)[0]}"


# =================================================================== helpers
def _expired(value, now: datetime) -> bool:
    if not value:
        return False
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when < now


__all__ = ["detect", "parse_cloud_files", "parse_kms", "parse_acm", "parse_elb", "parse_generic", "Tier"]
