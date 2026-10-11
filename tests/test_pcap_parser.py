"""Phase 2c: the PCAP parser.

Part 1 runs the real tshark pipeline on the organisers' network.pcap and checks
every session against ground_truth.yaml (setups, ports, verdicts, counts).
Part 2 uses three REAL handshakes recorded with openssl s_server/s_client on
loopback (tests/fixtures/*.pcap) for what the starter kit does not contain:
certificates, ServerKeyExchange, RSA-1024/SHA-1, a non-standard port.
Part 3 tests the session logic without tshark (synthetic rows).
"""
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from quantumtrace.catalog import load_catalog
from quantumtrace.classify import classify
from quantumtrace.models import Tier, Usage
from quantumtrace.parsers import pcap as pcap_mod
from quantumtrace.parsers.pcap import build_sessions, find_tshark, ssh_findings, tls_findings
from quantumtrace.scan import scan_path

HERE = Path(__file__).parent
GT = yaml.safe_load((HERE / "ground_truth.yaml").read_text())
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
PCAP = KIT / "network-capture" / "network.pcap"
FIX = HERE / "fixtures"
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)

needs_tshark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")
needs_kit = pytest.mark.skipif(not PCAP.is_file(), reason=f"starter kit pcap not found at {PCAP}")


# ===================================================================== part 1: the starter kit
@pytest.fixture(scope="module")
def kit():
    return scan_path(PCAP, now=NOW)


@pytest.fixture(scope="module")
def sessions(kit):
    """stream number -> list of findings."""
    out = defaultdict(list)
    for f in kit.findings:
        out[int(re.search(r"stream (\d+)", f.location).group(1))].append(f)
    return out


@needs_tshark
@needs_kit
def test_session_counts(kit):
    assert dict(kit.pcap.sessions) == GT["totals"]["pcap_sessions"]
    assert not kit.warnings


@needs_tshark
@needs_kit
@pytest.mark.parametrize("setup", GT["pcap"], ids=lambda s: s["setup"])
def test_each_setup_matches_ground_truth(sessions, setup):
    """Find the sessions whose negotiated algorithms are exactly this setup's, then check
    how many there are, on which ports, and that each gets the expected verdict."""
    want = {c["algorithm"] for c in setup["components"]}
    matched = []
    for stream, fs in sessions.items():
        negotiated = {f.algorithm for f in fs if "offered" not in f.flags}
        if negotiated == want:
            matched.append(fs)
    assert len(matched) == setup["sessions"]
    ports = Counter(int(fs[0].asset.rsplit(":", 1)[1]) for fs in matched)
    assert dict(ports) == setup["ports"]
    exp = setup["expected"]
    for fs in matched:
        cls = [f.classification for f in fs]
        assert max((c.tier for c in cls), key=lambda t: t.severity) is Tier(exp["tier"])
        assert any(c.hndl for c in cls) is exp["hndl"]
        flags = set().union(*(c.flags for c in cls))
        assert set(exp.get("flags", [])) <= flags


@needs_tshark
@needs_kit
def test_pqc_readiness_and_offered_capabilities(kit):
    p = kit.pcap
    assert (p.pq_sessions, p.sessions["tls"]) == (7, 97)
    assert p.tls_versions == {"1.2": 54, "1.3": 43}
    assert p.offered_groups["X25519MLKEM768"] == 7            # only the 7 hybrid clients offer it
    assert set(p.offered_sig_schemes) == {"rsa_pkcs1_sha256", "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"}


@needs_tshark
@needs_kit
def test_protocol_upgrades_are_recognised(kit):
    smtp = {f.asset for f in kit.findings if "starttls-smtp" in f.flags}
    pg = {f.asset for f in kit.findings if "starttls-postgres" in f.flags}
    assert len(smtp) == 11 and all(a.endswith(":587") for a in smtp)
    assert len(pg) == 8 and all(a.endswith(":5432") for a in pg)


@needs_tshark
@needs_kit
def test_ssh_downgrade_risk_only_on_legacy_servers(sessions):
    legacy = [fs for fs in sessions.values() if any(f.algorithm == "ssh-rsa" for f in fs)]
    modern = [fs for fs in sessions.values() if any(f.algorithm == "rsa-sha2-512" for f in fs)]
    assert len(legacy) == 14 and len(modern) == 10
    for fs in legacy:
        offered = {f.algorithm for f in fs if "downgrade-risk" in f.flags}
        assert offered == {"diffie-hellman-group1-sha1", "3des-cbc"}
    assert not any("downgrade-risk" in f.flags for fs in modern for f in fs)


@needs_tshark
@needs_kit
def test_every_finding_is_traceable(kit):
    for f in kit.findings:
        assert re.fullmatch(r"network\.pcap:stream \d+, frame \d+", f.location)
        assert re.fullmatch(r".+:\d+", f.asset) and f.evidence
    tls13 = [f for f in kit.findings if f.context.startswith("TLS 1.3") and f.usage is Usage.PROTOCOL]
    assert tls13 and all("certificate-not-observable" in f.flags for f in tls13)


# ===================================================================== part 2: real recorded handshakes
def _fixture(name, now=NOW):
    res = scan_path(FIX / f"{name}.pcap", now=now)
    return {(f.usage, f.algorithm): f for f in res.findings}, res


@needs_tshark
def test_tls12_ecdhe_rsa_with_certificate():
    fs, res = _fixture("tls12-ecdhe-rsa")
    assert res.pcap.sessions == {"tls": 1}
    assert fs[(Usage.KEY_EXCHANGE, "x25519")].classification.hndl
    assert (Usage.SIGNATURE, "rsa_pss_rsae_sha256") in fs
    cert_key = fs[(Usage.CERTIFICATE, "RSA")]
    assert cert_key.key_size == 2048 and not cert_key.classification.hndl     # a certificate is "future" risk
    assert (Usage.CERTIFICATE, "SHA256withRSA") in fs


@needs_tshark
def test_legacy_static_rsa_with_rsa1024_sha1_certificate():
    fs, _ = _fixture("tls12-static-rsa-legacy")
    suite = fs[(Usage.PROTOCOL, "TLS_RSA_WITH_AES_128_CBC_SHA")]
    assert "no-forward-secrecy" in suite.classification.flags and suite.classification.hndl
    key = fs[(Usage.CERTIFICATE, "RSA")]
    assert key.key_size == 1024 and {"weak-key-size", "classically-broken"} <= key.classification.flags
    assert "classically-broken" in fs[(Usage.CERTIFICATE, "SHA1withRSA")].classification.flags


@needs_tshark
def test_ecdsa_certificate_on_non_standard_port():
    fs, _ = _fixture("tls12-ecdsa-8443")
    cert = fs[(Usage.CERTIFICATE, "secp256r1")]
    assert cert.asset.endswith(":8443") and cert.classification.tier is Tier.CRITICAL
    assert (Usage.SIGNATURE, "ecdsa_secp256r1_sha256") in fs


@needs_tshark
def test_certificate_expiry_depends_on_the_date():
    fs, _ = _fixture("tls12-ecdhe-rsa", now=datetime(2028, 1, 1, tzinfo=timezone.utc))
    assert "expired" in fs[(Usage.CERTIFICATE, "RSA")].flags
    fs, _ = _fixture("tls12-ecdhe-rsa", now=datetime(2027, 9, 25, tzinfo=timezone.utc))
    assert "expiring-soon" in fs[(Usage.CERTIFICATE, "RSA")].flags


@needs_tshark
@pytest.mark.parametrize("missing", [{"pkcs1.modulus", "pkcs1.namedCurve"},            # like tshark 4.6
                                     {"pkcs1.modulus", "pkcs1.namedCurve", "x509af.algorithm.id"}])
def test_certificates_do_not_depend_on_tshark_x509_fields(monkeypatch, missing):
    """Regression (found on the user's tshark 4.6): certificate details used to come from
    tshark's pkcs1.* dissector fields, which are absent there. Raw DER bytes are decoded instead."""
    real = pcap_mod.available_fields
    monkeypatch.setattr(pcap_mod, "available_fields", lambda t: real(t) - missing)
    fs, _ = _fixture("tls12-ecdhe-rsa")
    assert fs[(Usage.CERTIFICATE, "RSA")].key_size == 2048
    fs, _ = _fixture("tls12-ecdsa-8443")
    assert fs[(Usage.CERTIFICATE, "secp256r1")].key_size == 256


@needs_tshark
def test_fallback_without_raw_certificate_bytes(monkeypatch):
    real = pcap_mod.available_fields
    monkeypatch.setattr(pcap_mod, "available_fields", lambda t: real(t) - {"tls.handshake.certificate"})
    fs, _ = _fixture("tls12-static-rsa-legacy")
    assert (Usage.CERTIFICATE, "SHA1withRSA") in fs and (Usage.CERTIFICATE, "RSA") in fs


@needs_tshark
def test_self_signed_certificate_is_flagged():
    fs, _ = _fixture("tls12-ecdhe-rsa")
    assert "self-signed" in fs[(Usage.CERTIFICATE, "RSA")].flags


@needs_tshark
def test_corrupt_capture_gives_a_warning_not_a_crash(tmp_path):
    bad = tmp_path / "broken.pcap"
    bad.write_bytes(b"this is not a capture file")
    res = scan_path(bad)
    assert res.findings == [] and res.warnings and "broken.pcap" in res.warnings[0]


# ===================================================================== part 3: logic without tshark
CAT = load_catalog()


def _row(stream, src, sport, dst, dport, **fields):
    base = {"frame.number": "10", "frame.protocols": "eth:ip:tcp:tls", "tcp.stream": str(stream),
            "ip.src": src, "ip.dst": dst, "tcp.srcport": str(sport), "tcp.dstport": str(dport)}
    return {**base, **fields}


def test_ssh_rfc4253_rule_picks_first_client_choice_the_server_supports():
    rows = [
        _row(0, "10.0.0.1", 50000, "10.0.0.2", 22, **{"tcp.flags.syn": "True", "tcp.flags.ack": "False"}),
        _row(0, "10.0.0.1", 50000, "10.0.0.2", 22, **{
            "frame.protocols": "eth:ip:tcp:ssh", "ssh.message_code": "20",
            "ssh.kex_algorithms": "mlkem768x25519-sha256,curve25519-sha256,ext-info-c",
            "ssh.server_host_key_algorithms": "ssh-ed25519",
            "ssh.encryption_algorithms_client_to_server": "aes256-gcm@openssh.com,aes128-ctr"}),
        _row(0, "10.0.0.2", 22, "10.0.0.1", 50000, **{
            "frame.protocols": "eth:ip:tcp:ssh", "ssh.message_code": "20",
            "ssh.kex_algorithms": "curve25519-sha256,diffie-hellman-group1-sha1",
            "ssh.server_host_key_algorithms": "ssh-ed25519",
            "ssh.encryption_algorithms_client_to_server": "aes128-ctr,aes256-gcm@openssh.com"}),
    ]
    [s] = build_sessions(rows).values()
    found = {f.usage: f.algorithm for f in ssh_findings(s, "x.pcap", CAT) if "offered" not in f.flags}
    assert found[Usage.KEY_EXCHANGE] == "curve25519-sha256"      # client's 1st choice (ML-KEM) not supported by server
    assert found[Usage.ENCRYPTION] == "aes256-gcm@openssh.com"   # client order wins, not server order
    assert Usage.MAC not in found                                  # AEAD cipher: MAC unused


def test_ssh_with_only_one_kexinit_is_marked_inferred():
    rows = [_row(1, "10.0.0.2", 22, "10.0.0.1", 50001, **{
        "frame.protocols": "eth:ip:tcp:ssh", "ssh.message_code": "20",
        "ssh.kex_algorithms": "curve25519-sha256", "ssh.server_host_key_algorithms": "ssh-ed25519"})]
    [s] = build_sessions(rows).values()
    found = ssh_findings(s, "x.pcap", CAT)
    assert found and all("negotiation-inferred" in f.flags and f.confidence < 1 for f in found)


def test_tls10_and_client_ready_for_pq_but_server_not():
    rows = [
        _row(2, "10.0.0.1", 50002, "10.0.0.3", 443, **{
            "tls.handshake.type": "1", "tls.handshake.extensions_server_name": "legacy.test",
            "tls.handshake.extensions_supported_group": "0x11ec;0x001d"}),
        _row(2, "10.0.0.3", 443, "10.0.0.1", 50002, **{
            "tls.handshake.type": "2;12;14", "tls.handshake.version": "0x0301",
            "tls.handshake.ciphersuite": "0xc013", "tls.handshake.server_named_curve": "0x001d"}),
    ]
    [s] = build_sessions(rows).values()
    found = {f.usage: classify(f) for f in tls_findings(s, "x.pcap", CAT, NOW)}
    assert "tls1.0-negotiated" in found[Usage.PROTOCOL].flags
    kex = found[Usage.KEY_EXCHANGE]
    assert kex.algorithm == "x25519" and "client-offered-pq" in kex.flags     # fix is server-side only
    assert kex.asset == "legacy.test:443"


def test_missing_tshark_is_a_warning(monkeypatch, tmp_path):
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1")
    monkeypatch.setattr(pcap_mod, "find_tshark", lambda: None)
    res = scan_path(p)
    assert res.findings == [] and "tshark not found" in res.warnings[0]
