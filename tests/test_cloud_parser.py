"""Phase 2a: the cloud parser, end to end.

Part 1 runs the real scan pipeline on the organisers' cloud-posture/ folder and
compares every asset with ground_truth.yaml.
Part 2 uses small hand-made JSON files for cases the starter kit does not
contain (PQ policy, unknown policy, GCP/Azure exports, non-crypto JSON).
"""
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from quantumtrace.models import Tier, Usage
from quantumtrace.parsers.cloud import detect
from quantumtrace.scan import scan_path
from quantumtrace.summary import summarise

HERE = Path(__file__).parent
GT = yaml.safe_load((HERE / "ground_truth.yaml").read_text())
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
CLOUD = KIT / "cloud-posture"
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)      # fixed "today" so expiry checks are reproducible

needs_kit = pytest.mark.skipif(not CLOUD.is_dir(), reason=f"starter kit not found at {CLOUD}")


# ===================================================================== part 1: the starter kit
@pytest.fixture(scope="module")
def result():
    return scan_path(CLOUD, now=NOW)


@pytest.fixture(scope="module")
def assets(result):
    return {a.asset: a for a in summarise(result.findings)}


def gt_items():
    for section, key in (("cloud_kms", "alias"), ("cloud_certificates", "domain"), ("cloud_listeners", "listener")):
        for item in GT[section]:
            yield pytest.param(section, item[key], item, id=f"{section}:{item[key]}")


@needs_kit
def test_all_three_files_detected(result):
    assert sorted(result.files["cloud"]) == ["acm_certificates.json", "kms_key_inventory.json",
                                             "load_balancer_listeners.json"]


@needs_kit
@pytest.mark.parametrize("section,asset_id,item", list(gt_items()))
def test_asset_verdict_matches_ground_truth(assets, section, asset_id, item):
    assert asset_id in assets, f"parser produced no finding for {asset_id}"
    a = assets[asset_id]
    exp = item["expected"]
    assert a.tier is Tier(exp["tier"])
    assert a.hndl is exp["hndl"]
    assert set(exp.get("flags", [])) <= a.flags, f"missing {set(exp.get('flags', [])) - a.flags}"
    assert set(item.get("parser_flags", [])) <= a.flags, f"missing {set(item.get('parser_flags', [])) - a.flags}"
    assert not set(item.get("absent_flags", [])) & a.flags
    if "replacement_standard" in exp:
        assert any(exp["replacement_standard"] in r for r in a.replacements)


@needs_kit
@pytest.mark.parametrize("section,asset_id,item", [p for p in gt_items() if "components" in p.values[2]])
def test_parser_reports_the_raw_names_from_ground_truth(assets, section, asset_id, item):
    """Recall at the name level: every algorithm the ground truth lists is really emitted."""
    seen = {f.algorithm for f in assets[asset_id].findings}
    expected = {c["algorithm"] for c in item["components"]}
    assert expected <= seen, f"missing {expected - seen}"


@needs_kit
@pytest.mark.parametrize("section,key", [("cloud_kms", "alias"), ("cloud_certificates", "domain"),
                                         ("cloud_listeners", "listener")])
def test_totals(assets, section, key):
    ids = {item[key] for item in GT[section]}
    counts = Counter(assets[i].tier.value for i in ids)
    assert dict(counts) == GT["totals"][section]


@needs_kit
def test_no_extra_assets(assets):
    """Precision at the asset level: nothing invented beyond the ground truth."""
    expected = ({i["alias"] for i in GT["cloud_kms"]} | {i["domain"] for i in GT["cloud_certificates"]}
                | {i["listener"] for i in GT["cloud_listeners"]})
    assert set(assets) == expected


@needs_kit
def test_every_finding_is_traceable(result):
    files = set(result.files["cloud"])
    for f in result.findings:
        assert f.source == "cloud" and ":$." in f.location and f.evidence
        assert f.location.split(":$.")[0] in files, f.location      # points at the real file (was "deletion:" for KMS)
        assert f.classification is not None


@needs_kit
def test_certificate_is_joined_to_its_listener(assets):
    legacy = assets["legacy-tcp.internal.example.com"].findings[0]
    assert "legacy-tcp-nlb:8443" in legacy.related
    listener = assets["legacy-tcp-nlb:8443"].findings[0]
    assert any(":certificate/" in r for r in listener.related)


@needs_kit
def test_expiry_depends_on_the_date():
    early = summarise(scan_path(CLOUD / "acm_certificates.json",
                                now=datetime(2026, 1, 1, tzinfo=timezone.utc)).findings)
    legacy = next(a for a in early if a.asset == "legacy-tcp.internal.example.com")
    assert "expired" not in legacy.flags


# ===================================================================== part 2: synthetic inputs
def _scan_doc(tmp_path, doc, name="export.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return summarise(scan_path(p, now=NOW).findings)


def _listener(policy, proto="HTTPS"):
    return {"LoadBalancers": [{"LoadBalancerName": "lb", "Scheme": "internet-facing", "Listeners": [
        {"ListenerArn": "arn:aws:elasticloadbalancing:eu-west-1:1:listener/app/lb/1/2",
         "Protocol": proto, "Port": 443, "SslPolicy": policy}]}]}


def test_pq_policy_offers_hybrid_groups_with_classical_fallback(tmp_path):
    [a] = _scan_doc(tmp_path, _listener("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"))
    algs = {f.algorithm: f for f in a.findings}
    assert {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"} <= set(algs)
    assert algs["X25519MLKEM768"].classification.tier is Tier.SAFE
    assert "downgrade-risk" in algs["ECDHE"].flags          # classical fallback is called out
    assert "no-forward-secrecy" not in a.flags


def test_unknown_policy_is_reported_not_guessed(tmp_path):
    [a] = _scan_doc(tmp_path, _listener("ELBSecurityPolicy-Custom-2030-01"))
    assert a.tier is Tier.UNKNOWN and "unknown-policy" in a.flags


def test_gcp_kms_export_via_generic_walker(tmp_path):
    doc = {"cryptoKeys": [
        {"name": "projects/p/locations/l/keyRings/r/cryptoKeys/signer", "purpose": "ASYMMETRIC_SIGN",
         "versionTemplate": {"algorithm": "EC_SIGN_P256_SHA256"}},
        {"name": "projects/p/locations/l/keyRings/r/cryptoKeys/pq", "purpose": "ASYMMETRIC_SIGN",
         "versionTemplate": {"algorithm": "PQ_SIGN_ML_DSA_65"}},
        {"name": "projects/p/locations/l/keyRings/r/cryptoKeys/data", "purpose": "ENCRYPT_DECRYPT",
         "versionTemplate": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}}]}
    assert detect(doc) == "generic"
    tiers = sorted(a.tier.value for a in _scan_doc(tmp_path, doc))
    assert tiers == ["CRITICAL", "SAFE", "SAFE"]


def test_azure_key_vault_jwk(tmp_path):
    doc = {"keys": [{"kid": "https://vault/keys/k1", "kty": "RSA", "key_size": 2048, "key_ops": ["sign"]},
                    {"kid": "https://vault/keys/k2", "kty": "EC", "crv": "P-384"}]}
    assets = {a.asset: a for a in _scan_doc(tmp_path, doc)}
    assert assets["https://vault/keys/k1"].tier is Tier.CRITICAL
    assert assets["https://vault/keys/k1"].findings[0].key_size == 2048
    assert assets["https://vault/keys/k2"].tier is Tier.CRITICAL


def test_non_crypto_json_produces_nothing(tmp_path):
    doc = {"name": "my-app", "version": "1.2.3", "dependencies": {"left-pad": "^1.3.0"},
           "description": "uses modes and desserts", "hash": "abc123"}
    assert _scan_doc(tmp_path, doc, "package.json") == []


def test_tcp_listener_is_low_confidence_plaintext(tmp_path):
    [a] = _scan_doc(tmp_path, _listener(None, proto="TCP"))
    assert a.tier is Tier.PLAINTEXT and "tls-not-terminated-here" in a.flags
    assert a.findings[0].confidence < 1


def test_kms_usage_mapping(tmp_path):
    doc = {"Keys": [{"KeyId": "k", "AliasName": "alias/agree", "KeyUsage": "KEY_AGREEMENT",
                     "KeySpec": "ECC_NIST_P256", "KeyAgreementAlgorithms": ["ECDH"]}]}
    [a] = _scan_doc(tmp_path, doc)
    assert a.findings[0].usage is Usage.KEY_EXCHANGE and a.hndl
