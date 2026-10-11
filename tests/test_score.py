"""Phase 3: the Quantum Risk Score. Rules on hand-made findings, then the starter kit by hand."""
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from quantumtrace.classify import classify
from quantumtrace.models import Finding, Tier, Usage
from quantumtrace.scan import scan_path
from quantumtrace.score import (EXPOSURE_DEFAULT, EXPOSURE_HNDL, EXPOSURE_LONG_LIVED, compute, exposure,
                                finding_severity)

HERE = Path(__file__).parent
GT = yaml.safe_load((HERE / "ground_truth.yaml").read_text())
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
needs_kit = pytest.mark.skipif(not (KIT / "network-capture").is_dir(), reason=f"starter kit not found at {KIT}")


def F(algorithm, usage=Usage.UNKNOWN, source="code", asset="a.py", **kw):
    return classify(Finding(source=source, location=f"{asset}:1", algorithm=algorithm, usage=usage, asset=asset, **kw))


# ===================================================================== severity S
@pytest.mark.parametrize("finding,expected", [
    (F("RSA", Usage.SIGNATURE, key_size=3072), 1.0),          # CRITICAL
    (F("plaintext", Usage.PROTOCOL), 1.0),                     # PLAINTEXT
    (F("AES", Usage.ENCRYPTION, key_size=128), 0.4),           # MEDIUM
    (F("SHA-1", Usage.HASH), 0.7),                             # MEDIUM + broken today
    (F("RSA", Usage.SIGNATURE, key_size=1024), 1.0),           # CRITICAL + broken: capped at 1
    (F("AES", Usage.ENCRYPTION, key_size=256), 0.0),           # SAFE
    (F("ML-KEM-768", Usage.KEY_EXCHANGE), 0.0),
    (F("x25519", Usage.KEY_EXCHANGE, flags={"offered", "downgrade-risk"}), 0.5),   # only a fallback
    (F("insecure-random"), 0.0),                               # INFO: not scored
    (F("Cipher:unresolved"), 0.0),                             # UNKNOWN: not scored
])
def test_severity(finding, expected):
    assert finding_severity(finding) == expected


# ===================================================================== exposure E
def test_exposure():
    assert exposure([F("x25519", Usage.KEY_EXCHANGE)])[0] == EXPOSURE_HNDL
    assert exposure([F("plaintext", Usage.PROTOCOL)])[0] == EXPOSURE_HNDL
    assert exposure([F("RSA_2048", Usage.CERTIFICATE)])[0] == EXPOSURE_LONG_LIVED
    assert exposure([F("RSA", Usage.SIGNATURE, details={"key": "k1", "key_type": "private-key"})])[0] == EXPOSURE_LONG_LIVED
    assert exposure([F("Ed25519", Usage.SIGNATURE)])[0] == EXPOSURE_DEFAULT
    assert exposure([F("MD5", Usage.HASH)])[0] == EXPOSURE_DEFAULT


# ===================================================================== aggregation
def test_asset_takes_its_worst_finding_and_sources_weigh_the_same():
    findings = [
        F("AES", Usage.ENCRYPTION, key_size=256, asset="safe.py"),                  # S 0,   E 1.0
        F("AES", Usage.ENCRYPTION, key_size=128, asset="mixed.py"),                 # worst of mixed.py ...
        F("RSA", Usage.SIGNATURE, key_size=3072, asset="mixed.py"),                 # ... S 1, E 1.0
        F("x25519", Usage.KEY_EXCHANGE, source="pcap", asset="h:443"),              # S 1, E 1.5
        F("X25519MLKEM768", Usage.KEY_EXCHANGE, source="pcap", asset="pq:443"),     # S 0, E 1.0
        F("cryptography", Usage.LIBRARY, asset="requirements.txt", purl="pkg:pypi/cryptography@46.0.5",
          version="46.0.5"),                                                         # INFO: not scored
    ]
    s = compute(findings)
    assert s.by_source == {"network": round(100 * 1.5 / 2.5, 1), "code": 50.0}
    assert s.score == round((60.0 + 50.0) / 2, 1)
    assert s.pooled == round(100 * (1 + 1.5) / (1 + 1 + 1.5 + 1), 1)
    assert sum(1 for a in s.assets if not a.scored) == 1


def test_more_migration_means_lower_score():
    before = compute([F("x25519", Usage.KEY_EXCHANGE, source="pcap", asset=f"h{i}:443") for i in range(4)])
    after = compute([F("x25519", Usage.KEY_EXCHANGE, source="pcap", asset=f"h{i}:443") for i in range(3)]
                    + [F("X25519MLKEM768", Usage.KEY_EXCHANGE, source="pcap", asset="h3:443")])
    assert before.score == 100.0 and after.score < before.score
    assert compute([]).score is None


# ===================================================================== the starter kit
@pytest.fixture(scope="module")
def kit():
    r = scan_path(KIT, now=NOW)
    return r, compute(r.findings, r.pcap.pqc_readiness)


@needs_kit
def test_kit_score_matches_ground_truth(kit):
    r, s = kit
    exp = GT["scores"]["kit"]
    assert s.score == exp["quantum_risk_score"]
    assert s.by_source == exp["by_source"]
    assert len(s.assets) == exp["assets"] and len(r.findings) == exp["findings"]
    assert sum(1 for a in s.assets if a.tier is Tier.CRITICAL and a.hndl) == exp["hndl_assets"]
    assert 0 <= s.score <= 100 and s.pqc_readiness == pytest.approx(7 / 97)


@needs_kit
def test_kit_score_by_hand(kit):
    """Recompute the cloud sub-score from the ground truth alone (not from our own S/E code):
    KMS 6 CRITICAL keys (E 1.3) + 4 SAFE keys (E 1.3); ACM 5 CRITICAL certs (E 1.3);
    ELB 5 CRITICAL HNDL listeners (E 1.5) + 1 PLAINTEXT listener (E 1.5); the redirect (INFO) is not scored."""
    _, s = kit
    num = 6 * 1.3 + 5 * 1.3 + 5 * 1.5 + 1 * 1.5
    den = 10 * 1.3 + 5 * 1.3 + 6 * 1.5
    # one KMS key is used for encryption -> HNDL (E 1.5 instead of 1.3)
    num, den = num + 0.2, den + 0.2
    assert s.by_source["cloud"] == round(100 * num / den, 1)
