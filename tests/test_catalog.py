"""The catalog must be internally consistent: every check here guards against a
typo in catalog.yaml silently turning a Critical finding into an Unknown one."""
import pytest

from quantumtrace.catalog import load_catalog, norm
from quantumtrace.classify import classify_name
from quantumtrace.models import Tier

CAT = load_catalog()
VALID_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
                    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"}


def test_catalog_loads_and_is_not_empty():
    assert len(CAT.algorithms) >= 50
    assert len(CAT.tls_cipher_suites) >= 30


@pytest.mark.parametrize("key,entry", CAT.algorithms.items())
def test_entry_has_required_fields(key, entry):
    for f in ("name", "kind", "threat", "primitive"):
        assert f in entry, f"{key} missing {f}"
    assert ("tier" in entry) != ("tier_by_bits" in entry), f"{key}: exactly one of tier / tier_by_bits"
    assert entry["primitive"] in VALID_PRIMITIVES, f"{key}: bad CycloneDX primitive"


@pytest.mark.parametrize("key,entry", CAT.algorithms.items())
def test_shor_vulnerable_means_critical_and_nist_level_zero(key, entry):
    if entry["threat"] == "shor":
        assert entry["tier"] == "CRITICAL"
        assert entry["nist_level"] == 0


@pytest.mark.parametrize("key", CAT.algorithms)
def test_every_alias_resolves_back_to_its_own_entry(key):
    for alias in CAT.algorithms[key].get("aliases", []):
        name = alias["name"] if isinstance(alias, dict) else str(alias)
        assert CAT.resolve(name).key == key, f"alias {name!r} does not resolve to {key}"


def test_composites_only_reference_existing_algorithms():
    for name, specs in CAT.composites.items():
        for spec in specs:
            assert spec["alg"] in CAT.algorithms, f"composite {name} -> unknown {spec['alg']}"


@pytest.mark.parametrize("table", ["tls_cipher_suites", "tls_groups", "tls_signature_schemes"])
def test_every_tls_registry_name_is_recognised(table):
    for code, name in getattr(CAT, table).items():
        c = classify_name(name)
        assert c.tier is not Tier.UNKNOWN, f"{table} 0x{code:04X} {name} -> UNKNOWN"


def test_codepoint_lookup():
    assert CAT.tls_suite_name("0x002f") == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert CAT.tls_group_name(4588) == "X25519MLKEM768"
    assert CAT.tls_group_name("0x001d") == "x25519"
    assert CAT.tls_sigscheme_name(0x0807) == "ed25519"


def test_norm_ignores_case_punctuation_and_vendor_suffix():
    assert norm("ECC_NIST_P256") == norm("ecc-nist-p256") == "eccnistp256"
    assert norm("aes256-gcm@openssh.com") == "aes256gcm"


@pytest.mark.parametrize("policy", CAT.aws_elb_policies)
def test_every_elb_policy_cipher_is_recognised(policy):
    entry = CAT.aws_elb_policies[policy]
    assert entry["tls_versions"] and entry["ciphers"]
    for name in entry["ciphers"] + entry.get("pq_groups", []):
        c = classify_name(name)
        assert all(comp.catalog_key for comp in c.components), f"{policy}: {name} not fully recognised"


def test_pq_policies_are_named_pq():
    for name, entry in CAT.aws_elb_policies.items():
        assert ("-PQ-" in name) == bool(entry.get("pq_groups")), name
