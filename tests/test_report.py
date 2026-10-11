"""Phase 3: the JSON audit report, the migration roadmap and the CLI outputs."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quantumtrace.classify import classify
from quantumtrace.cli import main
from quantumtrace.models import Finding, Usage
from quantumtrace.report import analyse, roadmap
from quantumtrace.scan import scan_path
from quantumtrace.score import compute

HERE = Path(__file__).parent
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
INFRA = HERE / "fixtures" / "sample-infra"
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
needs_kit = pytest.mark.skipif(not (KIT / "network-capture").is_dir(), reason=f"starter kit not found at {KIT}")


def F(algorithm, usage=Usage.UNKNOWN, source="code", asset="a.py", **kw):
    return classify(Finding(source=source, location=f"{asset}:1", algorithm=algorithm, usage=usage, asset=asset, **kw))


@pytest.fixture(scope="module")
def kit():
    r = scan_path(KIT, now=NOW)
    return r, analyse(r, "kit", timestamp=NOW)


def rows_by_current(report):
    return {r["current"]: r for r in report["roadmap"]}


# ===================================================================== roadmap rules
def test_priorities():
    rows = {r["current"]: r for r in roadmap(compute([
        F("x25519", Usage.KEY_EXCHANGE, source="pcap", asset="h:443"),                 # HNDL -> 1
        F("plaintext", Usage.PROTOCOL, source="pcap", asset="p:80"),                   # plaintext -> 1
        F("SHA1withRSA", Usage.CERTIFICATE, asset="c.pem"),                            # broken today -> 2
        F("Ed25519", Usage.SIGNATURE, asset="s.py"),                                   # future forgery -> 3
        F("AES", Usage.ENCRYPTION, key_size=128, asset="e.py"),                        # Grover -> 4
        F("cryptography", Usage.LIBRARY, asset="requirements.txt",
          purl="pkg:pypi/cryptography@46.0.5", version="46.0.5"),                      # enabler -> 5
    ]))}
    assert rows["X25519"]["priority"] == 1 and rows["X25519"]["hndl"]
    assert rows["No encryption (plaintext)"]["priority"] == 1
    assert rows["SHA-1"]["priority"] == 2 and rows["RSA"]["priority"] == 2
    assert rows["Ed25519"]["priority"] == 3
    assert rows["AES (128)"]["priority"] == 4
    assert rows["pyca/cryptography 46.0.5"]["priority"] == 5
    assert "48.0.0" in rows["pyca/cryptography 46.0.5"]["replacement"]


def test_fallback_only_rows_are_less_urgent():
    rows = {r["current"]: r for r in roadmap(compute([
        F("X25519MLKEM768", Usage.KEY_EXCHANGE, source="config", asset="vpn:443"),
        F("x25519", Usage.KEY_EXCHANGE, source="config", asset="vpn:443", flags={"offered", "downgrade-risk"}),
    ]))}
    assert rows["X25519"]["priority"] == 2                     # HNDL, but only as a fallback next to ML-KEM


def test_rows_group_an_algorithm_family_and_count_assets_once():
    rows = {r["current"]: r for r in roadmap(compute([
        F("RSA", Usage.SIGNATURE, key_size=2048, asset="a.py"), F("RSA", Usage.SIGNATURE, key_size=3072, asset="a.py"),
        F("RSA", Usage.SIGNATURE, key_size=4096, asset="b.py")]))}
    row = rows["RSA (2048, 3072, 4096)"]
    assert row["asset_count"] == 2 and row["finding_count"] == 3 and row["standard"] == "FIPS 204"


# ===================================================================== the starter kit
@needs_kit
def test_kit_roadmap(kit):
    _, (_, _, report) = kit
    rows = report["roadmap"]
    assert [r["priority"] for r in rows] == sorted(r["priority"] for r in rows)
    assert all(r["hndl"] or r["current"].startswith("No encryption") for r in rows if r["priority"] == 1)
    by = rows_by_current(report)
    assert by["No encryption (plaintext)"]["asset_count"] == 15
    assert by["HMAC-SHA1"]["priority"] == 4                      # not broken: just Grover
    assert by["SHA-1"]["priority"] == 2                          # SHA-1 hashes / signatures: broken today
    assert by["pyca/cryptography 46.0.5"]["priority"] == 5
    assert rows[0]["rank"] == 1 and rows[0]["priority"] == 1


@needs_kit
def test_kit_report_summary(kit):
    r, (score, bom, report) = kit
    s = report["summary"]
    assert s["findings"] == 416 and s["assets"] == 183 and s["hndl_assets"] == 120
    assert s["assets_by_tier"] == {"CRITICAL": 136, "MEDIUM": 9, "SAFE": 20, "PLAINTEXT": 15, "INFO": 3}
    assert report["score"]["quantum_risk_score"] == score.score
    assert report["cbom"]["valid"] is True
    assert report["pqc_readiness"]["network"]["pq_sessions"] == 7
    assert {lib["library"] for lib in report["libraries"]} == {"cryptography", "stdlib"}
    ids = {f.id for f in r.findings}
    assert all(set(a["findings"]) <= ids for a in report["assets"])
    json.dumps(report)                                           # serialisable


# ===================================================================== CLI
def test_cli_writes_all_outputs(tmp_path, capsys):
    out = tmp_path / "report"
    assert main(["scan", str(INFRA), "--out", str(out), "--now", "2026-10-11"]) == 0
    printed = capsys.readouterr().out
    assert "QUANTUM RISK SCORE" in printed and "valid CycloneDX 1.6" in printed and "P1" in printed
    assert {p.name for p in out.iterdir()} == {"findings.json", "report.json", "cbom.json"}
    bom = json.loads((out / "cbom.json").read_text())
    assert bom["specVersion"] == "1.6" and bom["metadata"]["timestamp"] == "2026-10-11T00:00:00Z"
    report = json.loads((out / "report.json").read_text())
    findings = json.loads((out / "findings.json").read_text())
    assert report["summary"]["findings"] == len(findings)
    assert main(["validate", str(out / "cbom.json")]) == 0
    bom["components"][0]["type"] = "spaceship"
    (out / "bad.json").write_text(json.dumps(bom))
    assert main(["validate", str(out / "bad.json")]) == 1


def test_same_scan_twice_gives_identical_files(tmp_path):
    for name in ("a", "b"):
        main(["scan", str(INFRA), "--out", str(tmp_path / name), "--now", "2026-10-11"])
    for f in ("findings.json", "report.json"):
        assert (tmp_path / "a" / f).read_text() == (tmp_path / "b" / f).read_text(), f
    a, b = (json.loads((tmp_path / n / "cbom.json").read_text()) for n in "ab")
    a.pop("serialNumber"), b.pop("serialNumber")                 # unique per BOM, as the spec asks
    assert a == b
