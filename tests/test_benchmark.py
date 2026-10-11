"""Phase 5: validation.

Part 1 checks the measuring instrument itself (metric arithmetic, family grouping, label hygiene),
part 2 pins the benchmark results (every dataset, every source) so a regression shows up as a
failing test, part 3 guards the honesty of the hold-out (labels frozen, first-run numbers kept),
part 4 tests the scanner fixes the hold-out and adversarial sets led to.
"""
import hashlib
import json
import os
import textwrap
from pathlib import Path

import pytest

from quantumtrace import benchmark as B
from quantumtrace.classify import classify_name
from quantumtrace.cli import main
from quantumtrace.models import Tier, Usage
from quantumtrace.scan import scan_path

HERE = Path(__file__).parent
SUITE = HERE / "benchmarks"
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
needs_kit = pytest.mark.skipif(not (KIT / "network-capture").is_dir(), reason=f"starter kit not found at {KIT}")


# ===================================================================== part 1: the instrument
def _row(found=True, tier=("CRITICAL", "CRITICAL"), hndl=(True, True), fam=None, sizes=(), flags=(), src="code"):
    t, p = tier
    return {"dataset": "t", "source": src, "asset": "a", "found": found, "tier_true": t, "tier_pred": p,
            "tier_ok": t == p, "hndl_true": hndl[0], "hndl_pred": hndl[1],
            "families": fam, "key_sizes": list(sizes), "flags": list(flags)}


def test_metric_arithmetic():
    rows = [_row(fam={"tp": ["RSA", "AES"], "fp": ["MD5"], "fn": []}),                     # TP hndl
            _row(hndl=(False, True), fam={"tp": ["AES"], "fp": [], "fn": ["SHA-256"]}),    # FP hndl
            _row(found=False, tier=("SAFE", "MISSING"), hndl=(True, False),                # FN hndl
                 fam={"tp": [], "fp": [], "fn": ["ML-KEM-768"]}),
            _row(tier=("MEDIUM", "SAFE"), hndl=(None, True), fam=None,                     # hndl not labelled
                 sizes=[{"family": "AES", "bits": 128, "ok": False}],
                 flags=[{"flag": "x", "expect": True, "ok": True}])]
    m = B.metrics(rows, false_assets=1)
    assert m["assets"] == 4 and m["detection"] == {"found": 3, "false_assets": 1, "precision": 0.75, "recall": 0.75}
    assert (m["algorithms"]["tp"], m["algorithms"]["fp"], m["algorithms"]["fn"]) == (3, 1, 2)
    assert m["algorithms"]["precision"] == 0.75 and m["algorithms"]["recall"] == 0.6
    assert m["algorithms"]["f1"] == round(2 * 0.75 * 0.6 / 1.35, 4)
    assert m["verdict"]["correct"] == 2 and m["verdict"]["accuracy"] == 0.5
    assert m["verdict"]["confusion"]["SAFE"] == {"MISSING": 1} and m["verdict"]["confusion"]["MEDIUM"] == {"SAFE": 1}
    assert m["hndl"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 0, "precision": 0.5, "recall": 0.5}
    assert m["key_sizes"] == {"ok": 0, "total": 1, "accuracy": 0.0} and m["flags"]["accuracy"] == 1.0


def test_metrics_with_nothing_to_measure_are_none_not_100():
    m = B.metrics([])
    assert m["detection"]["precision"] is None and m["algorithms"]["f1"] is None and m["hndl"]["recall"] is None
    zero = B.metrics([_row(fam={"tp": [], "fp": ["MD5"], "fn": ["AES"]})])
    assert zero["algorithms"]["precision"] == 0.0 and zero["algorithms"]["f1"] == 0.0


def test_families_group_curves_and_ignore_spelling():
    assert B.families_of("P-384") == B.families_of("secp384r1") == B.families_of("ECDSA") == {"ECC"}
    assert B.families_of("SHA256withECDSA") == {"ECC", "SHA-256"}
    assert B.families_of("HmacSHA1") == B.families_of("hmac-sha1") == {"HMAC-SHA1"}
    assert B.families_of("plaintext") == set()                          # a verdict, not an algorithm
    assert B.families_of("TLS_RSA_WITH_AES_128_CBC_SHA") == {"RSA", "AES", "HMAC-SHA1"}
    assert B.families_of("no-such-cipher-xyz") == {"?no-such-cipher-xyz"}   # unknown never matches a label


def test_labels_must_be_readable(tmp_path):
    (tmp_path / "x.yaml").write_text("dataset: x\nroot: .\nassets:\n"
                                     "  - {asset: a.py, source: code, tier: SAFE, hndl: false, algorithms: [AES, Fernett]}\n")
    with pytest.raises(ValueError, match="Fernett"):
        B.load_labelled(tmp_path / "x.yaml")


def test_compare_missing_allowed_and_offered():
    t = B.Truth("d", "h:22", "network", "CRITICAL", True, {"DH", "SHA-1"}, allowed={"3DES"}, offered={"3DES"},
                key_sizes={"DH": 2048}, flags={"classically-broken"}, absent_flags={"hybrid"})
    miss = B.compare(t, None)
    assert miss["tier_pred"] == "MISSING" and miss["families"]["fn"] == ["DH", "SHA-1"]
    assert miss["offered"]["missing"] == ["3DES"] and not any(k["ok"] for k in miss["key_sizes"])
    p = B.Predicted("h:22", "network", "CRITICAL", True, {"DH", "SHA-1", "3DES", "MD5"}, set(), {("DH", 2048)},
                    {"classically-broken", "hybrid"}, [])
    r = B.compare(t, p)
    assert r["families"]["fp"] == ["MD5"]                           # 3DES is allowed, MD5 is not
    assert r["offered"]["missing"] == [] and r["key_sizes"][0]["ok"]
    assert [f["ok"] for f in r["flags"]] == [True, False]           # hybrid must NOT be there


def test_network_offered_algorithms_are_not_negotiated_ones():
    from quantumtrace.classify import classify
    from quantumtrace.models import Finding
    used = classify(Finding("pcap", "x.pcap#1", "curve25519-sha256", Usage.KEY_EXCHANGE, asset="h:22"))
    offered = classify(Finding("pcap", "x.pcap#1", "3des-cbc", Usage.ENCRYPTION, asset="h:22", flags={"offered"}))
    p = B.predicted_assets([used, offered])[("network", "h:22")]
    assert p.families == {"X25519", "SHA-256"} and p.offered == {"3DES"}
    code = classify(Finding("config", "c:1", "3des-cbc", Usage.ENCRYPTION, asset="c", flags={"offered"}))
    assert B.predicted_assets([code])[("config", "c")].families == {"3DES"}     # configs: offered IS the content


def test_threat_follows_the_public_key_part():
    th = lambda n, u="unknown": B.predicted_threat(classify_name(n, Usage(u)).components)   # noqa: E731
    assert th("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "protocol") == "shor"
    assert th("mlkem768x25519-sha256", "key_exchange") == "none"
    assert th("TLS_AES_256_GCM_SHA384", "protocol") == "grover" and th("plaintext") == "none"


# ===================================================================== part 2: pinned results
@pytest.fixture(scope="module")
def res():
    return B.run(SUITE, kit=KIT)


def _perfect(m):
    return (m["detection"]["precision"] == m["detection"]["recall"] == 1.0
            and m["algorithms"]["f1"] in (1.0, None) and m["verdict"]["accuracy"] == 1.0
            and m["hndl"]["precision"] in (1.0, None) and m["hndl"]["recall"] in (1.0, None)
            and m["key_sizes"]["ok"] == m["key_sizes"]["total"] and m["flags"]["ok"] == m["flags"]["total"])


@pytest.mark.parametrize("name, assets", [("holdout", 5), ("adversarial", 12), ("sample-infra", 19)])
def test_labelled_datasets(res, name, assets):
    d = res["datasets"][name]
    assert d["all"]["assets"] == assets
    assert _perfect(d["all"]), B.problems(d)
    assert all(_perfect(m) for m in d["by_source"].values())
    assert not d["unexpected"] and all(x["ok"] for x in d["decoys"])
    if d.get("libraries"):
        assert d["libraries"]["fp"] == d["libraries"]["fn"] == d["libraries"]["not_libraries_reported"] == []


@needs_kit
def test_kit(res):
    d = res["datasets"]["kit"]
    assert d["all"]["assets"] == 181 and set(d["by_source"]) == {"network", "code", "cloud"}
    assert _perfect(d["all"]), B.problems(d)[:10]
    assert [(s["setup"], s["assigned"]) for s in d["pcap_setups"]] == [
        ("tls12-static-rsa", 54), ("tls13-x25519", 36), ("tls13-hybrid-pq", 7), ("ssh-legacy", 14),
        ("ssh-modern", 10), ("http-plaintext", 14)] and all(s["ok"] for s in d["pcap_setups"])
    legacy = [r for r in d["rows"] if r.get("offered")]
    assert len(legacy) == 14 and all(not r["offered"]["missing"] for r in legacy)   # 3des-cbc fallback seen


@needs_kit
def test_kit_setup_counts_are_really_checked():
    ds = B.load_kit(HERE / "ground_truth.yaml", KIT)
    ds.setups[0].ports = {443: 34, 587: 10, 636: 10}          # same total, wrong split
    ds.setups[1].sessions = 35
    d = B.evaluate(ds)
    assert [s["ok"] for s in d["pcap_setups"]][:3] == [False, False, True]


def test_classification_benchmark(res):
    c = res["classification"]
    assert c["cases"] == 85 and c["accuracy"] == {"tier": 1.0, "threat": 1.0, "hndl": 1.0}, c["misses"]


def test_benchmark_catches_a_broken_scanner(monkeypatch):
    """The instrument must have teeth: call MD5 and AES-128 SAFE and the hold-out numbers must drop."""
    import sys
    C = sys.modules["quantumtrace.classify"]
    real = C.build_component

    def lying(part, usage, flags, cat):
        comp = real(part, usage, flags, cat)
        if comp.catalog_key in ("MD5", "AES"):         # Grover-weak things called safe
            comp.tier = Tier.SAFE
        return comp
    monkeypatch.setattr(C, "build_component", lying)
    d = B.evaluate(B.load_labelled(SUITE / "holdout.yaml"))
    assert d["by_source"]["code"]["verdict"]["accuracy"] < 1.0                # js/crypto-utils.js is MEDIUM (MD5, AES-128)


def test_dirty_decoy_and_unlabelled_asset_cost_precision(tmp_path):
    (tmp_path / "corpus" / "decoys").mkdir(parents=True)
    (tmp_path / "corpus" / "decoys" / "fake.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "corpus" / "real.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    (tmp_path / "corpus" / "extra.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    (tmp_path / "t.yaml").write_text("dataset: t\nroot: corpus\nassets:\n"
                                     "  - {asset: real.py, source: code, tier: SAFE, hndl: false, algorithms: [SHA-256]}\n"
                                     "decoys: [decoys/fake.py]\n")
    d = B.evaluate(B.load_labelled(tmp_path / "t.yaml"))
    assert [x["ok"] for x in d["decoys"]] == [False] and [u["asset"] for u in d["unexpected"]] == ["extra.py"]
    assert d["by_source"]["code"]["detection"] == {"found": 1, "false_assets": 2, "precision": 0.3333, "recall": 1.0}
    assert d["all"]["verdict"]["accuracy"] == 1.0


def test_cli_benchmark(tmp_path, capsys):
    assert main(["benchmark", "--only", "holdout", "classification", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "| code | 4 | 100% / 100%" in out and "decoys clean 5/5" in out and "85 names" in out
    data = json.loads((tmp_path / "benchmark.json").read_text())
    assert set(data["datasets"]) == {"holdout"} and "kit" not in data["skipped"]
    assert "## holdout" in (tmp_path / "benchmark.md").read_text()
    assert main(["benchmark", "--suite", str(tmp_path)]) == 1                  # no suite there


def test_cli_benchmark_reads_suite_and_kit_from_the_environment(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("QT_SUITE", str(tmp_path))                              # the Docker image sets these
    assert main(["benchmark"]) == 1 and str(tmp_path) in capsys.readouterr().out
    monkeypatch.setenv("QT_SUITE", str(SUITE))
    monkeypatch.setenv("QT_KIT", str(tmp_path / "no-kit"))
    assert main(["benchmark", "--only", "kit"]) == 0
    assert f"starter kit not found at {tmp_path / 'no-kit'}" in capsys.readouterr().out


# ===================================================================== part 3: honesty guards
def test_holdout_and_adversarial_are_frozen():
    """Labels and files were frozen before the first scan. Editing them to fit the tool fails here."""
    for line in (SUITE / "FROZEN.sha256").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        assert hashlib.sha256((SUITE / name).read_bytes()).hexdigest() == digest, f"{name} changed after freezing"
    listed = {line.split(maxsplit=1)[1] for line in (SUITE / "FROZEN.sha256").read_text().splitlines()}
    on_disk = {str(p.relative_to(SUITE)) for d in ("holdout", "adversarial") for p in (SUITE / d).rglob("*")
               if p.is_file() and "__pycache__" not in p.parts}
    assert on_disk <= listed, "new hold-out / adversarial files must be frozen too"


def test_first_run_numbers_are_kept():
    """What the scanner scored the FIRST time it saw these files (before any fix). The slide quotes these."""
    hold = json.loads((SUITE / "results" / "holdout-first-run.json").read_text())["datasets"]["holdout"]
    assert hold["all"]["verdict"]["accuracy"] == 1.0 and hold["all"]["algorithms"]["f1"] == 1.0
    assert hold["all"]["key_sizes"] == {"ok": 3, "total": 4, "accuracy": 0.75}
    adv = json.loads((SUITE / "results" / "adversarial-first-run.json").read_text())["datasets"]["adversarial"]
    assert adv["all"]["verdict"]["accuracy"] == 0.6667 and adv["all"]["algorithms"]["recall"] == 0.7358
    assert adv["all"]["detection"]["recall"] == 0.6667 and sum(x["ok"] for x in adv["decoys"]) == 2


# ===================================================================== part 4: the fixes
def _scan(tmp_path, name, code):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(code))
    return scan_path(tmp_path).findings


def test_aes_key_size_ignores_an_rsa_size_constant(tmp_path):
    fs = _scan(tmp_path, "a.py", """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        TOKEN_KEY_BITS = 2048
        def enc(d):
            key = AESGCM.generate_key(bit_length=192)
            return AESGCM(key).encrypt(b"n" * 12, d, None)
        """)
    aes = next(f for f in fs if f.algorithm == "AESGCM")
    assert aes.key_size == 192 and aes.classification.tier is Tier.MEDIUM


def test_size_hint_outside_valid_aes_sizes_is_not_used(tmp_path):
    fs = _scan(tmp_path, "b.py", """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        RSA_KEY_BITS = 3072
        def enc(key, d):
            return AESGCM(key).encrypt(b"n" * 12, d, None)
        """)
    aes = next(f for f in fs if f.algorithm == "AESGCM")
    assert aes.key_size is None and aes.classification.tier is Tier.UNKNOWN


def test_python_local_objects_named_like_modules(tmp_path):
    fs = _scan(tmp_path, "c.py", """
        class H:
            def md5(self, x): return x
        hashlib = H()
        random = H()
        hashlib.md5("a")
        """)
    assert fs == []


def test_python_fernet_and_jwt(tmp_path):
    fs = _scan(tmp_path, "d.py", """
        import jwt
        from jose import jwt as jose_jwt
        from cryptography.fernet import Fernet
        ALGS = ["RS256", "ES384"]
        box = Fernet(Fernet.generate_key())
        jwt.encode({}, "k")
        jwt.encode({}, key, algorithm="PS512")
        jwt.decode(t, key, algorithms=ALGS)
        jose_jwt.encode({}, key, algorithm="EdDSA")
        """)
    got = sorted((f.algorithm, f.key_size, f.mode) for f in fs)
    assert got == sorted([("AES", 128, "cbc"), ("HMAC-SHA256", None, None), ("HS256", None, None),
                          ("PS512", None, None), ("RS256", None, None), ("ES384", None, None),
                          ("EdDSA", None, None)])
    tiers = {f.algorithm: f.classification.tier for f in fs}
    assert tiers["AES"] is Tier.MEDIUM and tiers["HS256"] is Tier.SAFE and tiers["ES384"] is Tier.CRITICAL


def test_go_tls_config_constants(tmp_path):
    fs = _scan(tmp_path, "e.go", """
        package main
        import "crypto/tls"
        var cfg = &tls.Config{
            CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
            CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256},
            MinVersion:       tls.VersionTLS12,
        }
        """)
    got = {f.algorithm: (f.usage, f.classification.tier) for f in fs}
    assert got == {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": (Usage.PROTOCOL, Tier.CRITICAL),
                   "TLS_RSA_WITH_3DES_EDE_CBC_SHA": (Usage.PROTOCOL, Tier.CRITICAL),
                   "X25519MLKEM768": (Usage.KEY_EXCHANGE, Tier.SAFE),
                   "secp256r1": (Usage.KEY_EXCHANGE, Tier.CRITICAL)}


def test_go_tls_from_another_package_is_ignored(tmp_path):
    fs = _scan(tmp_path, "f.go", """
        package main
        import tls "example.com/mytls"
        var x = tls.TLS_RSA_WITH_RC4_128_SHA
        """)
    assert fs == []


def test_regex_fallback_lists(tmp_path):
    fs = _scan(tmp_path, "g.js", """
        const REMOVED_ALGORITHMS = ["md5", "sha1"];
        const LEGACY = [
          'des-ede3-cbc',
        ];
        const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
        jwt.verify(t, k, { algorithms: ['RS256'] });
        const tlsOpts = { ciphers: [
          'ECDHE-RSA-AES128-GCM-SHA256',
        ] };
        """)
    got = {(f.algorithm, f.key_size) for f in fs}
    assert got == {("rsa", 3072), ("RS256", None), ("ECDHE-RSA-AES128-GCM-SHA256", None)}


def test_regex_fallback_recovers_after_an_unbalanced_bracket(tmp_path):
    fs = _scan(tmp_path, "h.js", """
        const looksLikeAList = /[a-z/;
        const DIGEST = 'sha1';
        """)
    assert [f.algorithm for f in fs] == ["sha1"]


@pytest.mark.parametrize("name, fams", [("RS256", {"RSA", "SHA-256"}), ("PS384", {"RSA", "SHA-384"}),
                                        ("ES256", {"ECC", "SHA-256"}), ("ES512", {"ECC", "SHA-512"}),
                                        ("HS512", {"HMAC-SHA512"}), ("RSA-OAEP-256", {"RSA", "SHA-256"}),
                                        ("ECDH-ES+A256KW", {"ECC"}), ("A128GCM", {"AES"}),
                                        ("A256CBC-HS512", {"AES", "HMAC-SHA512"})])
def test_jose_names(name, fams):
    assert B.families_of(name) == fams


def test_jose_tiers():
    assert classify_name("A128GCM").tier is Tier.MEDIUM and classify_name("A256GCM").tier is Tier.SAFE
    assert classify_name("A256GCM").components[0].mode == "gcm"
    assert classify_name("RSA-OAEP-256").hndl and not classify_name("RS256").hndl
    assert [c.catalog_key for c in classify_name("ES512").components] == ["EC-P521", "SHA-512"]
    assert [c.catalog_key for c in classify_name("ES384").components] == ["EC-P384", "SHA-384"]


def test_null_cipher_suite_is_plaintext_not_hndl():
    c = classify_name("TLS_RSA_WITH_NULL_SHA256", Usage.PROTOCOL)
    assert c.tier is Tier.PLAINTEXT and not c.hndl
    assert classify_name("TLS_RSA_WITH_AES_128_CBC_SHA", Usage.PROTOCOL).hndl        # unchanged


def test_generic_cloud_names_and_usage(tmp_path):
    (tmp_path / "keys.json").write_text(json.dumps({
        "gcp": [{"name": "projects/p/cryptoKeys/k1", "purpose": "ASYMMETRIC_DECRYPT",
                 "versionTemplate": {"algorithm": "RSA_DECRYPT_OAEP_2048_SHA256"}}],
        "jwks": {"keys": [{"kid": "sig-1", "kty": "EC", "crv": "P-256", "use": "sig"},
                          {"kid": "enc-1", "kty": "RSA", "alg": "RSA-OAEP-256", "key_ops": ["wrapKey"]},
                          {"kty": "OKP", "crv": "X25519", "key_ops": ["deriveBits"]}]}}))
    fs = scan_path(tmp_path).findings
    by = {(f.asset, f.algorithm): f for f in fs}
    k1 = by[("projects/p/cryptoKeys/k1", "RSA_DECRYPT_OAEP_2048_SHA256")]
    assert k1.classification.hndl and k1.usage is Usage.ENCRYPTION
    assert by[("sig-1", "P-256")].usage is Usage.SIGNATURE and not by[("sig-1", "P-256")].classification.hndl
    assert by[("enc-1", "RSA-OAEP-256")].classification.hndl
    x = next(f for f in fs if f.algorithm == "X25519")
    assert x.usage is Usage.KEY_EXCHANGE and x.asset.startswith("keys.json:$.jwks.keys")   # no id: path
