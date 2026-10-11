"""Phase 3: the CycloneDX 1.6 CBOM.

Every CBOM we produce must pass the OFFICIAL CycloneDX 1.6 JSON schema (cyclonedx-python-lib)
and our reference-integrity check; and the content must be right: OIDs, NIST levels, certificates,
keys, protocols, libraries, FIPS 203/204/205 mapping, and a trace back to every finding.
"""
import copy
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quantumtrace.cbom import build_cbom, integrity_errors, split_location, validate
from quantumtrace.models import Usage
from quantumtrace.scan import scan_path
from quantumtrace.score import compute

HERE = Path(__file__).parent
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
INFRA = HERE / "fixtures" / "sample-infra"
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
SERIAL = "urn:uuid:00000000-0000-4000-8000-000000000000"
needs_kit = pytest.mark.skipif(not (KIT / "network-capture").is_dir(), reason=f"starter kit not found at {KIT}")


def make(path):
    r = scan_path(path, now=NOW)
    return r, build_cbom(r.findings, compute(r.findings, r.pcap.pqc_readiness), target="t", serial=SERIAL,
                         timestamp=NOW)


@pytest.fixture(scope="module")
def kit():
    return make(KIT)


@pytest.fixture(scope="module")
def infra():
    return make(INFRA)


def comps(bom, asset_type=None, type_=None):
    return [c for c in bom["components"] if (asset_type is None or c.get("cryptoProperties", {}).get("assetType")
                                             == asset_type) and (type_ is None or c["type"] == type_)]


def props(c, name):
    return [p["value"] for p in c.get("properties", []) if p["name"] == name]


def by_ref(bom):
    return {c["bom-ref"]: c for c in bom["components"] + bom.get("services", [])}


# ===================================================================== validity
@needs_kit
def test_kit_cbom_is_valid_cyclonedx_16(kit):
    ok, msgs = validate(kit[1])
    assert ok is True, msgs


def test_infra_cbom_is_valid_cyclonedx_16(infra):
    ok, msgs = validate(infra[1])
    assert ok is True, msgs


def test_validator_rejects_broken_cboms(infra):
    bom = infra[1]
    bad = copy.deepcopy(bom)
    comps(bad, "algorithm")[0]["cryptoProperties"]["algorithmProperties"]["primitive"] = "quantum"
    assert validate(bad)[0] is False
    bad = copy.deepcopy(bom)
    comps(bad, "certificate")[0]["cryptoProperties"]["certificateProperties"]["notValidAfter"] = "next year"
    assert validate(bad)[0] is False
    bad = copy.deepcopy(bom)
    bad["dependencies"][0]["dependsOn"].append("crypto/algorithm/does-not-exist")
    assert integrity_errors(bad) and validate(bad)[0] is False
    bad = copy.deepcopy(bom)
    bad["components"].append(dict(bad["components"][0]))
    assert any("duplicate" in e for e in integrity_errors(bad))


def test_deterministic_output(infra):
    _, again = make(INFRA)
    assert json.dumps(again, sort_keys=True) == json.dumps(infra[1], sort_keys=True)


# ===================================================================== algorithms
@needs_kit
def test_algorithm_facts(kit):
    algs = {c["bom-ref"]: c for c in comps(kit[1], "algorithm")}
    ap = lambda ref: algs[ref]["cryptoProperties"]["algorithmProperties"]           # noqa: E731
    assert algs["crypto/algorithm/aes-128-gcm"]["cryptoProperties"]["oid"] == "2.16.840.1.101.3.4.1.6"
    assert {"primitive": "ae", "mode": "gcm", "nistQuantumSecurityLevel": 1}.items() <= ap("crypto/algorithm/aes-128-gcm").items()
    assert ap("crypto/algorithm/x25519mlkem768")["primitive"] == "kem"
    assert ap("crypto/algorithm/x25519mlkem768")["nistQuantumSecurityLevel"] == 3
    assert "encapsulate" in ap("crypto/algorithm/x25519mlkem768")["cryptoFunctions"]
    assert algs["crypto/algorithm/sha1withrsa"]["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.5"
    assert ap("crypto/algorithm/sha-1")["cryptoFunctions"] == ["digest"]             # even inside SHA1withRSA
    # RSA used for signing and RSA used for key transport are different assets
    assert ap("crypto/algorithm/rsa-2048/signature")["primitive"] == "signature"
    assert ap("crypto/algorithm/rsa-2048/pke")["primitive"] == "pke"
    for c in algs.values():
        tier = props(c, "quantumtrace:tier")[0]
        if tier == "CRITICAL" and c["bom-ref"] != "crypto/algorithm/sha1withrsa":
            assert c["cryptoProperties"]["algorithmProperties"].get("nistQuantumSecurityLevel") == 0, c["bom-ref"]


@needs_kit
def test_fips_mapping(kit):
    bom = kit[1]
    std = {s["bom-ref"]: s for s in bom["definitions"]["standards"]}
    assert set(std) == {"standard/nist-fips-203", "standard/nist-fips-204", "standard/nist-fips-205"}
    assert any(r["url"] == "https://csrc.nist.gov/pubs/fips/203/final"
               for r in std["standard/nist-fips-203"]["externalReferences"])
    for c in comps(bom, "algorithm"):
        if props(c, "quantumtrace:tier") == ["CRITICAL"]:
            assert props(c, "quantumtrace:pqcReplacement"), c["bom-ref"]
            assert set(props(c, "quantumtrace:standardRef")) <= set(std) and props(c, "quantumtrace:standardRef")
    mlkem = next(c for c in comps(bom, "algorithm") if c["name"] == "X25519MLKEM768")
    assert props(mlkem, "quantumtrace:standardRef") == ["standard/nist-fips-203"]


# ===================================================================== certificates, keys, protocols
@needs_kit
def test_acm_certificate_and_its_public_key(kit):
    refs = by_ref(kit[1])
    cert = next(c for c in comps(kit[1], "certificate") if c["name"] == "legacy-tcp.internal.example.com")
    cp = cert["cryptoProperties"]["certificateProperties"]
    assert cp["notValidAfter"].startswith("2026-08-01")
    assert refs[cp["signatureAlgorithmRef"]]["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.5"   # SHA1withRSA
    key = refs[cp["subjectPublicKeyRef"]]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert key["type"] == "public-key" and key["size"] == 2048
    assert {"expired"} <= set(props(cert, "quantumtrace:flag"))


@needs_kit
def test_kms_keys_are_related_crypto_material(kit):
    keys = [c for c in comps(kit[1], "related-crypto-material") if c["name"].startswith("alias/")]
    assert len(keys) == 10
    partner = next(c for c in keys if c["name"] == "alias/partner-feed-decrypt")
    p = partner["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert p["type"] == "private-key" and p["size"] == 2048 and p["state"] == "active"
    assert p["creationDate"].endswith("Z") and p["id"].startswith("arn:aws:kms:")
    assert props(partner, "quantumtrace:hndl") == ["true"]                       # the only HNDL KMS key
    sym = [c for c in keys if c["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "secret-key"]
    assert sym and all(props(c, "quantumtrace:tier") == ["SAFE"] for c in sym)


@needs_kit
def test_network_protocol_profiles(kit):
    tls = {c["name"]: c for c in comps(kit[1], "protocol") if "negotiated" in props(c, "quantumtrace:observation")[0]
           and c["cryptoProperties"]["protocolProperties"]["type"] == "tls"}
    assert set(tls) == {"TLS 1.2: TLS_RSA_WITH_AES_128_CBC_SHA", "TLS 1.3: TLS_AES_128_GCM_SHA256 + X25519",
                        "TLS 1.3: TLS_AES_256_GCM_SHA384 + X25519MLKEM768"}
    legacy = tls["TLS 1.2: TLS_RSA_WITH_AES_128_CBC_SHA"]
    suite = legacy["cryptoProperties"]["protocolProperties"]["cipherSuites"][0]
    assert suite["identifiers"] == ["0x00", "0x2F"]
    assert set(suite["algorithms"]) == {"crypto/algorithm/rsa/pke", "crypto/algorithm/aes-128-cbc",
                                        "crypto/algorithm/hmac-sha1"}
    assert props(legacy, "quantumtrace:assets") == ["54"]
    assert props(tls["TLS 1.3: TLS_AES_256_GCM_SHA384 + X25519MLKEM768"], "quantumtrace:tier") == ["SAFE"]
    ssh = [c for c in comps(kit[1], "protocol") if c["cryptoProperties"]["protocolProperties"]["type"] == "ssh"]
    assert sorted(props(c, "quantumtrace:assets")[0] for c in ssh) == ["10", "14"]


def test_infra_offered_tls_profile_lists_every_suite(infra):
    r, bom = infra
    api = [f for f in r.findings if f.asset == "api.example.lab:443" and f.usage is Usage.PROTOCOL]
    deps = {d["ref"]: d for d in bom["dependencies"]}
    proto_ref = next(x for x in deps["service/api.example.lab:443"]["dependsOn"] if x.startswith("crypto/protocol/"))
    proto = by_ref(bom)[proto_ref]["cryptoProperties"]["protocolProperties"]
    assert proto["version"] == "1.0,1.1,1.2"
    assert sorted(s["name"] for s in proto["cipherSuites"]) == sorted(f.algorithm for f in api)


def test_infra_ml_dsa_certificate_and_files(infra):
    bom = infra[1]
    refs = by_ref(bom)
    vault = next(c for c in comps(bom, "certificate") if c["name"] == "vault.example.lab")
    sig = refs[vault["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"]]
    assert sig["name"] == "ML-DSA-65" and sig["cryptoProperties"]["oid"] == "2.16.840.1.101.3.4.3.18"
    assert sig["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    deps = {d["ref"]: d for d in bom["dependencies"]}
    assert vault["bom-ref"] in deps["file/nginx/certs/vault-mldsa.pem"]["dependsOn"]


# ===================================================================== libraries and traceability
@needs_kit
def test_libraries_provide_what_the_code_uses(kit):
    bom = kit[1]
    deps = {d["ref"]: d for d in bom["dependencies"]}
    lib = next(c for c in comps(bom, type_="library") if c.get("purl") == "pkg:pypi/cryptography@46.0.5")
    assert lib["version"] == "46.0.5" and "no-pqc-api" in props(lib, "quantumtrace:flag")
    assert "crypto/algorithm/ed25519" in deps[lib["bom-ref"]]["provides"]
    assert lib["bom-ref"] in deps["file/sample-repos/python/requirements.txt"]["dependsOn"]
    assert lib["bom-ref"] in deps["file/sample-repos/python/webhook_signature.py"]["dependsOn"]
    names = {c["name"] for c in comps(bom, type_="library")}
    assert {"Python standard library", "Java Cryptography Architecture (JDK)", "stdlib", "cryptography"} <= names


@needs_kit
def test_every_crypto_finding_is_traceable_in_the_cbom(kit):
    r, bom = kit
    seen = {i for c in bom["components"] for o in c.get("evidence", {}).get("occurrences", [])
            for i in re.findall(r"f-\d{4,}", o["additionalContext"])}
    missing = [f.id for f in r.findings
               if f.usage is not Usage.LIBRARY and f.id not in seen
               and not all(c.catalog_key == "PLAINTEXT" for c in f.classification.components)]   # no crypto: a service
    assert not missing


@needs_kit
def test_every_asset_hangs_off_the_target(kit):
    bom = kit[1]
    root = bom["dependencies"][0]
    assert root["ref"] == bom["metadata"]["component"]["bom-ref"]
    assert len(root["dependsOn"]) == 183                       # every asset of the scan
    services = {s["name"]: s for s in bom["services"]}
    assert props(services["intranet01.lab:80"], "quantumtrace:tier") == ["PLAINTEXT"]


def test_split_location():
    assert split_location("python/x.py:6") == ("python/x.py", 6, "")
    assert split_location("kms.json:$.Keys[2].KeySpec") == ("kms.json", None, "$.Keys[2].KeySpec")
    assert split_location("network.pcap:stream 4, frame 31") == ("network.pcap", None, "stream 4, frame 31")
    assert split_location("certs/legacy-sha1.crt") == ("certs/legacy-sha1.crt", None, "")


def test_private_key_material_never_reaches_the_cbom(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(65537, 2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    (tmp_path / "server.key").write_text(pem)
    r = scan_path(tmp_path, now=NOW)
    bom = build_cbom(r.findings, compute(r.findings), serial=SERIAL, timestamp=NOW)
    text = json.dumps(bom)
    assert pem.splitlines()[1] not in text and pem.splitlines()[5] not in text
    key = comps(bom, "related-crypto-material")[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert key["type"] == "private-key" and key["size"] == 2048 and "value" not in key
    assert validate(bom)[0] is True


def test_same_signature_algorithm_under_two_spellings_is_one_component():
    """ACM says ECDSA_WITH_SHA384 / SHA256WITHRSA, X.509 says SHA384withECDSA / SHA256withRSA: one asset each."""
    from quantumtrace.classify import classify
    from quantumtrace.models import Finding

    def cert(alg, cid, source):
        return classify(Finding(source=source, location=f"{cid}.pem:1", algorithm=alg, usage=Usage.CERTIFICATE,
                                asset=cid, details={"cert": cid, "cert_part": "signature"}))
    bom = build_cbom([cert("ECDSA_WITH_SHA384", "acm1", "cloud"), cert("SHA384withECDSA", "file1", "config"),
                      cert("SHA256WITHRSA", "acm2", "cloud"), cert("SHA256withRSA", "file2", "config")],
                     serial=SERIAL, timestamp=NOW)
    sigs = {c["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"] for c in comps(bom, "certificate")}
    assert sigs == {"crypto/algorithm/sha384withecdsa", "crypto/algorithm/sha256withrsa"}
    algs = {c["bom-ref"]: c for c in comps(bom, "algorithm")}
    assert algs["crypto/algorithm/sha384withecdsa"]["cryptoProperties"]["oid"] == "1.2.840.10045.4.3.3"
    assert validate(bom)[0] is True
