"""Check the classifier against the hand-verified ground truth of the starter kit.

Each asset in ground_truth.yaml lists the raw algorithm names its parser will
report. We classify them as separate findings (like the real pipeline will) and
check that the asset's worst tier, HNDL verdict and key flags match.
"""
from collections import Counter
from pathlib import Path

import pytest
import yaml

from quantumtrace.classify import classify
from quantumtrace.models import Finding, Tier, Usage

GT = yaml.safe_load((Path(__file__).parent / "ground_truth.yaml").read_text())
SECTIONS = ["code", "cloud_kms", "cloud_certificates", "cloud_listeners", "pcap"]


def asset_verdict(item):
    """Classify every component of one asset; return (worst tier, hndl, flags, replacements)."""
    results = []
    for comp in item["components"]:
        f = Finding(source="gt", location="gt", algorithm=comp["algorithm"],
                    usage=Usage(comp.get("usage", "unknown")), key_size=comp.get("key_size"),
                    mode=comp.get("mode"), flags=set(comp.get("flags", [])))
        results.append(classify(f).classification)
    worst = max((r.tier for r in results), key=lambda t: t.severity)
    flags = set().union(*(r.flags for r in results))
    replacements = [x for r in results for x in r.replacements]
    return worst, any(r.hndl for r in results), flags, replacements


def cases():
    out = []
    for section in SECTIONS:
        for item in GT[section]:
            ident = item.get("file") or item.get("alias") or item.get("domain") or item.get("listener") or item.get("setup")
            if "components" not in item:
                continue        # TLS listeners: only a policy name, checked end-to-end in test_cloud_parser.py
            out.append(pytest.param(section, item, id=f"{section}:{ident}"))
    return out


@pytest.mark.parametrize("section,item", cases())
def test_asset_matches_ground_truth(section, item):
    worst, hndl, flags, replacements = asset_verdict(item)
    exp = item["expected"]
    assert worst is Tier(exp["tier"])
    assert hndl is exp["hndl"]
    assert set(exp.get("flags", [])) <= flags, f"missing flags {set(exp.get('flags', [])) - flags}"
    if "replacement_standard" in exp:
        assert any(exp["replacement_standard"] in r for r in replacements)


@pytest.mark.parametrize("section", ["code", "cloud_kms", "cloud_certificates"])
def test_totals_per_source(section):
    counts = Counter(asset_verdict(item)[0].value for item in GT[section])
    assert dict(counts) == GT["totals"][section]


def test_pcap_session_counts_add_up():
    by_kind = Counter()
    for item in GT["pcap"]:
        kind = "ssh" if item["setup"].startswith("ssh") else "plaintext" if "plaintext" in item["setup"] else "tls"
        by_kind[kind] += item["sessions"]
        assert sum(item["ports"].values()) == item["sessions"]
    assert dict(by_kind) == GT["totals"]["pcap_sessions"]
