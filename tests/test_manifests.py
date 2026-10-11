"""Phase 2d: crypto libraries declared in dependency manifests, and their link to the code."""
import os
from pathlib import Path

import pytest
import yaml

from quantumtrace.catalog import load_catalog
from quantumtrace.classify import classify
from quantumtrace.models import Finding, Tier, Usage
from quantumtrace.parsers.manifests import _version, manifest_kind, parse_manifest_files
from quantumtrace.purl import make_purl, parse_purl, version_at_least
from quantumtrace.scan import scan_path

HERE = Path(__file__).parent
GT = yaml.safe_load((HERE / "ground_truth.yaml").read_text())
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
INFRA = HERE / "fixtures" / "sample-infra"
needs_kit = pytest.mark.skipif(not (KIT / "sample-repos").is_dir(), reason=f"starter kit not found at {KIT}")


def libraries(result):
    return {(f.asset, f.algorithm): f for f in result.findings if f.usage is Usage.LIBRARY}


# ===================================================================== the starter kit
@pytest.fixture(scope="module")
def kit():
    return scan_path(KIT / "sample-repos")


@needs_kit
@pytest.mark.parametrize("item", GT["libraries"], ids=[i["library"] for i in GT["libraries"]])
def test_kit_libraries_match_ground_truth(kit, item):
    lib = libraries(kit)[(item["file"], item["library"])]
    assert lib.purl == item["purl"]
    assert lib.classification.tier is Tier.INFO
    assert set(item["flags"]) <= lib.classification.flags
    assert sorted(lib.related) == sorted(item["used_by"])         # which files use it


@needs_kit
def test_kit_code_findings_carry_the_library_purl(kit):
    for item in GT["libraries"]:
        for file in item["used_by"]:
            code = [f for f in kit.findings if f.asset == file and f.usage is not Usage.LIBRARY
                    and f.library != "hashlib" and f.library != "hmac" and f.library != "random"]
            assert code and any(f.purl == item["purl"] for f in code), file


@needs_kit
def test_kit_has_exactly_two_libraries(kit):
    assert len(libraries(kit)) == len(GT["libraries"])


# ===================================================================== the sample infrastructure: one manifest per ecosystem
@pytest.fixture(scope="module")
def infra():
    return libraries(scan_path(INFRA))


INFRA_EXPECTED = [
    # (manifest, library, purl, flags that must be present)
    ("app-python/requirements.txt", "cryptography", "pkg:pypi/cryptography", {"version-range", "pqc-not-guaranteed"}),
    ("app-python/requirements.txt", "pycryptodome", "pkg:pypi/pycryptodome@3.20.0", set()),
    ("app-python/requirements.txt", "pycrypto", "pkg:pypi/pycrypto@2.6.1", {"deprecated-library"}),
    ("app-python/requirements.txt", "liboqs-python", "pkg:pypi/liboqs-python@0.10.0", {"pqc-library"}),
    ("app-go/go.mod", "stdlib", "pkg:golang/stdlib@1.22", {"no-pqc-api"}),
    ("app-go/go.mod", "golang.org/x/crypto", "pkg:golang/golang.org/x/crypto@v0.31.0", set()),
    ("app-go/go.mod", "github.com/cloudflare/circl", "pkg:golang/github.com/cloudflare/circl@v1.5.0", {"pqc-library"}),
    ("app-js/package.json", "crypto-js", "pkg:npm/crypto-js", {"deprecated-library", "version-range"}),
    ("app-js/package.json", "@noble/post-quantum", "pkg:npm/%40noble/post-quantum@0.2.1", {"pqc-library"}),
    ("app-js/package.json", "jsonwebtoken", "pkg:npm/jsonwebtoken@9.0.2", set()),
    ("app-java/pom.xml", "org.bouncycastle:bcprov-jdk15on", "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.70", {"deprecated-library"}),
    ("app-java/pom.xml", "org.bouncycastle:bcprov-jdk18on", "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.80",
     {"pqc-capable", "pqc-data-unverified"}),                      # ${bc.version} resolved from <properties>
    ("app-java/pom.xml", "io.jsonwebtoken:jjwt-api", "pkg:maven/io.jsonwebtoken/jjwt-api@0.12.6", set()),
    ("app-rust/Cargo.toml", "ring", "pkg:cargo/ring", {"version-range"}),
    ("app-rust/Cargo.toml", "rustls", "pkg:cargo/rustls", {"version-range"}),
    ("app-rust/Cargo.toml", "ml-kem", "pkg:cargo/ml-kem@0.2.1", {"pqc-library"}),
]


@pytest.mark.parametrize("manifest,name,purl,flags", INFRA_EXPECTED, ids=[e[1] for e in INFRA_EXPECTED])
def test_infra_libraries(infra, manifest, name, purl, flags):
    f = infra[(manifest, name)]
    assert f.purl == purl
    assert flags <= f.classification.flags, f"missing {flags - f.classification.flags}"
    assert f.classification.tier is Tier.INFO


def test_non_crypto_dependencies_are_ignored(infra):
    names = {n for _, n in infra}
    assert not names & {"requests", "express", "serde", "org.slf4j:slf4j-api", "golang.org/x/sys"}
    assert len(infra) == len(INFRA_EXPECTED)


def test_infra_python_code_linked_to_both_libraries():
    found = [f for f in scan_path(INFRA).findings if f.asset == "app-python/app.py" and f.library]
    purls = {f.library: f.purl for f in found}                    # (the pasted PEM certificate has no library)
    assert purls == {"cryptography": "pkg:pypi/cryptography", "pycryptodome": "pkg:pypi/pycryptodome@3.20.0"}


def test_infra_go_code_linked_to_stdlib_and_x_crypto():
    found = [f for f in scan_path(INFRA).findings if f.asset == "app-go/main.go"]
    assert {f.library: f.purl for f in found} == {
        "crypto/ecdh": "pkg:golang/stdlib@1.22",
        "golang.org/x/crypto/chacha20poly1305": "pkg:golang/golang.org/x/crypto@v0.31.0"}


# ===================================================================== building blocks
@pytest.mark.parametrize("spec,expected", [
    ("==46.0.5", ("46.0.5", "46.0.5", set())),
    (">=42", (None, ">=42", {"version-range"})),
    ("~=3.20", (None, "~=3.20", {"version-range"})),
    ("^4.2.0", (None, "^4.2.0", {"version-range"})),
    ("4.2.0", ("4.2.0", "4.2.0", set())),
    ("", (None, "", {"version-unpinned"})),
    ("*", (None, "", {"version-unpinned"})),
    (">=1.0; python_version < '3.8'", (None, ">=1.0", {"version-range"})),
])
def test_version_specs(spec, expected):
    assert _version(spec) == expected


def test_purl_round_trip_and_versions():
    for eco, name, ver in [("pypi", "cryptography", "46.0.5"), ("maven", "org.bouncycastle:bcprov-jdk18on", "1.80"),
                           ("npm", "@noble/post-quantum", "0.2.1"), ("golang", "golang.org/x/crypto", "v0.31.0")]:
        assert parse_purl(make_purl(eco, name, ver)) == (eco, name, ver)
    assert version_at_least("48.0.0", "48.0.0") and version_at_least("50.0.2", "48")
    assert not version_at_least("47.0.0", "48.0.0") and not version_at_least("1.9", "1.24")
    assert version_at_least("v1.24.3", "1.24")


def test_range_whose_lower_bound_already_has_pqc():
    f = Finding(source="code", location="x", algorithm="cryptography", usage=Usage.LIBRARY,
                purl="pkg:pypi/cryptography", version=">=48.0", flags={"version-range"})
    assert "pqc-capable" in classify(f).classification.flags


def test_manifest_kinds():
    assert manifest_kind(Path("requirements.txt")) == "requirements"
    assert manifest_kind(Path("requirements-dev.txt")) == "requirements"
    assert manifest_kind(Path("dev-requirements.txt")) == "requirements"
    assert manifest_kind(Path("package.json")) == "npm"
    assert manifest_kind(Path("package-lock.json")) is None
    assert manifest_kind(Path("notes.txt")) is None


def test_pyproject_and_gradle_and_broken_manifest(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["cryptography==48.0.1", "rich"]\n')
    (tmp_path / "build.gradle").write_text("dependencies {\n    implementation 'org.bouncycastle:bcprov-jdk18on:1.81'\n}\n")
    (tmp_path / "package.json").write_text("{ not json")
    found, warnings = parse_manifest_files(sorted(tmp_path.iterdir()), root=tmp_path, catalog=load_catalog())
    for f in found:
        classify(f)
    by = {f.algorithm: f for f in found}
    assert "pqc-capable" in by["cryptography"].classification.flags
    assert by["org.bouncycastle:bcprov-jdk18on"].location == "build.gradle:2"
    assert warnings == ["package.json: could not read npm manifest (JSONDecodeError)"]
