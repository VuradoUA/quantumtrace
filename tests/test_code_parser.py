"""Phase 2b: the code scanner, end to end.

Part 1 scans the organisers' sample-repos/ and compares every file with
ground_truth.yaml (tier, HNDL, flags, parser facts, raw names, key sizes).
Part 2 feeds small hand-written snippets for the traps that cost accuracy
points: comments/strings, aliased imports, multi-line calls, unknown key sizes,
library defaults, look-alike names, and the regex fallback for other languages.
"""
import os
import textwrap
from collections import Counter
from pathlib import Path

import pytest
import yaml

from quantumtrace.models import Tier, Usage
from quantumtrace.scan import scan_path
from quantumtrace.summary import summarise

HERE = Path(__file__).parent
GT = yaml.safe_load((HERE / "ground_truth.yaml").read_text())
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
REPOS = KIT / "sample-repos"
needs_kit = pytest.mark.skipif(not REPOS.is_dir(), reason=f"starter kit not found at {REPOS}")


# ===================================================================== part 1: the starter kit
@pytest.fixture(scope="module")
def result():
    return scan_path(REPOS)


@pytest.fixture(scope="module")
def assets(result):
    return {a.asset: a for a in summarise(result.findings)}


GT_CODE = [pytest.param(item, id=item["file"]) for item in GT["code"]]


@needs_kit
@pytest.mark.parametrize("item", GT_CODE)
def test_file_verdict_matches_ground_truth(assets, item):
    assert item["file"] in assets, f"no finding at all in {item['file']}"
    a, exp = assets[item["file"]], item["expected"]
    assert a.tier is Tier(exp["tier"])
    assert a.hndl is exp["hndl"]
    assert set(exp.get("flags", [])) <= a.flags, f"missing {set(exp.get('flags', [])) - a.flags}"
    assert set(item.get("parser_flags", [])) <= a.flags, f"missing {set(item.get('parser_flags', [])) - a.flags}"


@needs_kit
@pytest.mark.parametrize("item", GT_CODE)
def test_raw_names_and_key_sizes_are_found(assets, item):
    """Recall at the name level, plus the key size / mode the ground truth expects."""
    findings = assets[item["file"]].findings
    for comp in item["components"]:
        same = [f for f in findings if f.algorithm == comp["algorithm"]]
        assert same, f"{comp['algorithm']} not reported in {item['file']}"
        if "key_size" in comp:
            assert any(f.key_size == comp["key_size"] for f in same), f"{comp['algorithm']}: wrong key size"
        if "mode" in comp:
            modes = {c.mode for f in same for c in f.classification.components}
            assert comp["mode"] in modes, f"{comp['algorithm']}: mode {modes}"


@needs_kit
def test_totals(assets):
    counts = Counter(assets[i["file"]].tier.value for i in GT["code"])
    assert dict(counts) == GT["totals"]["code"]


@needs_kit
def test_no_extra_files(assets, result):
    """Precision at the file level: exactly the 24 source files have crypto findings; README is
    skipped; go.mod / requirements.txt only give LIBRARY inventory (Phase 2d, test_manifests.py)."""
    with_crypto = {name for name, a in assets.items() if any(f.usage is not Usage.LIBRARY for f in a.findings)}
    assert with_crypto == {i["file"] for i in GT["code"]}
    assert all(f.endswith((".py", ".java", ".go")) for f in result.files["code"])
    assert sorted(result.files["manifest"]) == ["go/go.mod", "python/requirements.txt"]
    assert result.skipped == ["README.md"]


@needs_kit
def test_every_finding_is_traceable(result):
    for f in result.findings:
        path, _, line = f.location.rpartition(":")
        assert (REPOS / path).is_file() and line.isdigit()
        assert f.library and f.evidence and f.classification is not None


@needs_kit
def test_no_hndl_in_sample_code(assets):
    """All asymmetric crypto in the samples is signing -> 'future' risk, never HNDL."""
    assert not any(a.hndl for a in assets.values())


# ===================================================================== part 2: synthetic snippets
def scan_snippet(tmp_path, name, code):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code))
    found = scan_path(p).findings
    return found, (summarise(found)[0] if found else None)


def test_comments_strings_and_lookalikes_are_ignored(tmp_path):
    found, _ = scan_snippet(tmp_path, "notes.py", '''
        # TODO: replace RSA and hashlib.md5 with something better
        DOC = "we used to call hashlib.sha1() here"
        def md5(x):            # a local function that happens to be called md5
            return x
        md5(b"data")
        modes = ["fast", "slow"]
    ''')
    assert found == []


def test_aliased_import_is_still_found(tmp_path):
    found, a = scan_snippet(tmp_path, "alias.py", '''
        import hashlib as h
        digest = h.md5(b"x").hexdigest()
    ''')
    assert [f.algorithm for f in found] == ["md5"] and a.tier is Tier.MEDIUM


def test_multiline_call_and_key_from_os_urandom(tmp_path):
    found, a = scan_snippet(tmp_path, "multi.py", '''
        import os
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = os.urandom(16)
        c = Cipher(
            algorithms.AES(
                key),
            modes.CBC(os.urandom(16)),
        )
    ''')
    [f] = found
    assert (f.key_size, f.mode) == (128, "cbc") and "hardcoded-key" not in f.flags
    assert a.tier is Tier.MEDIUM


def test_unknown_key_size_is_reported_as_unknown(tmp_path):
    _, a = scan_snippet(tmp_path, "unknown.py", '''
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        def seal(k, data, nonce):
            return AESGCM(k).encrypt(nonce, data, None)
    ''')
    assert a.tier is Tier.UNKNOWN and "key-size-unknown" in a.flags


def test_python_rsa_oaep_encryption_is_hndl(tmp_path):
    _, a = scan_snippet(tmp_path, "rsa_enc.py", '''
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ct = key.public_key().encrypt(b"secret", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                             algorithm=hashes.SHA256(), label=None))
    ''')
    assert a.tier is Tier.CRITICAL and a.hndl


def test_python_ecdh_and_pycryptodome(tmp_path):
    _, a = scan_snippet(tmp_path, "ecdh.py", '''
        from cryptography.hazmat.primitives.asymmetric import ec
        priv = ec.generate_private_key(ec.SECP384R1())
        shared = priv.exchange(ec.ECDH(), peer_public_key)
    ''')
    assert a.tier is Tier.CRITICAL and a.hndl
    found, a = scan_snippet(tmp_path, "legacy.py", '''
        from Crypto.Cipher import AES
        cipher = AES.new(b"sixteen byte key", AES.MODE_ECB)
    ''')
    [f] = found
    assert (f.key_size, f.mode) == (128, "ecb") and "hardcoded-key" in f.flags


def test_java_default_aes_mode_is_ecb(tmp_path):
    found, a = scan_snippet(tmp_path, "Legacy.java", '''
        import javax.crypto.Cipher;
        class Legacy { void f() throws Exception { Cipher c = Cipher.getInstance("AES"); } }
    ''')
    assert {"default-mode-ecb", "insecure-mode"} <= a.flags


def test_java_rsa_encryption_key_is_hndl(tmp_path):
    found, a = scan_snippet(tmp_path, "Vault.java", '''
        import java.security.KeyPairGenerator;
        import javax.crypto.Cipher;
        class Vault {
          private static final String RSA_MODE = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
          void f() throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(4096);
            Cipher c = Cipher.getInstance(RSA_MODE);
          }
        }
    ''')
    gen = next(f for f in found if f.algorithm == "RSA")
    assert gen.key_size == 4096 and gen.usage.value == "encryption"
    assert a.tier is Tier.CRITICAL and a.hndl


def test_java_securerandom_is_not_flagged(tmp_path):
    found, _ = scan_snippet(tmp_path, "Tok.java", '''
        import java.security.SecureRandom;
        class Tok { byte[] t() { byte[] b = new byte[16]; new SecureRandom().nextBytes(b); return b; } }
    ''')
    assert found == []


def test_go_curves_mlkem_and_rand_packages(tmp_path):
    found, a = scan_snippet(tmp_path, "main.go", '''
        package main
        import (
            "crypto/ecdsa"
            "crypto/elliptic"
            "crypto/mlkem"
            "crypto/rand"
            mrand "math/rand"
        )
        func main() {
            k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
            dk, _ := mlkem.GenerateKey768()
            b := make([]byte, 8)
            rand.Read(b)          // crypto/rand: fine
            _ = mrand.Intn(10)    // math/rand under an alias: weak
            _, _ = k, dk
        }
    ''')
    algs = {f.algorithm: f.classification.tier for f in found}
    assert algs["P-256"] is Tier.CRITICAL and algs["ML-KEM-768"] is Tier.SAFE
    assert [f.library for f in found if f.algorithm == "insecure-random"] == ["math/rand"]


def test_go_hmac_in_a_loop_without_xor_is_not_pbkdf2(tmp_path):
    found, _ = scan_snippet(tmp_path, "macs.go", '''
        package main
        import ("crypto/hmac"; "crypto/sha256")
        func sign(key []byte, msgs [][]byte) (out [][]byte) {
            for _, m := range msgs {
                h := hmac.New(sha256.New, key)
                h.Write(m)
                out = append(out, h.Sum(nil))
            }
            return
        }
    ''')
    assert "PBKDF2" not in {f.algorithm for f in found}


def test_regex_fallback_for_other_languages(tmp_path):
    found, a = scan_snippet(tmp_path, "app.js", '''
        const crypto = require('crypto');
        // const old = crypto.createHash('sha1');   <- commented out, must be ignored
        const h = crypto.createHash('md5').update(pw).digest('hex');
        const c = crypto.createCipheriv('aes-128-ecb', key, null);
        const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const label = "des";   // too generic on its own: ignored
    ''')
    assert sorted(f.algorithm for f in found) == ["aes-128-ecb", "md5", "rsa"]
    assert all("regex-fallback" in f.flags and f.confidence < 0.5 for f in found)
    assert a.tier is Tier.CRITICAL


def test_syntax_errors_still_scanned_but_flagged(tmp_path):
    found, a = scan_snippet(tmp_path, "broken.py", '''
        import hashlib
        def f(:
            return hashlib.sha1(b"x")
    ''')
    assert found and "parse-errors" in a.flags
