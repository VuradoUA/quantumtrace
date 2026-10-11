"""Dependency manifests (Phase 2d): which CRYPTOGRAPHIC LIBRARIES a project declares.

    requirements*.txt, pyproject.toml, Pipfile     (Python)
    go.mod                                         (Go; the `go` line = standard library version)
    package.json                                   (JavaScript)
    pom.xml, build.gradle, build.gradle.kts        (Java)
    Cargo.toml                                     (Rust)

Only libraries listed under `libraries:` in catalog.yaml are reported (requests, flask, ...
are not crypto). One Finding per declared crypto library, usage `library`, with a purl
(pkg:pypi/cryptography@46.0.5). The classifier then says whether that VERSION can already
do post-quantum crypto (flags pqc-capable / no-pqc-api / pqc-library / pq-tls-default).

`link_libraries` connects them to the code findings: python/report_export.py uses
`cryptography` -> its findings get the purl of python/requirements.txt's cryptography==46.0.5,
and the library finding lists the files that use it (traceability for the CBOM).
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:                 # Python 3.10: same parser, published as `tomli` (a dependency there)
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

from ..catalog import Catalog, load_catalog
from ..models import Finding, Usage
from ..purl import make_purl

FILENAMES = {"pyproject.toml": "pyproject", "pipfile": "pipfile", "go.mod": "gomod", "package.json": "npm",
             "pom.xml": "pom", "build.gradle": "gradle", "build.gradle.kts": "gradle", "cargo.toml": "cargo"}
REQUIREMENTS = re.compile(r"^requirements[\w.-]*\.txt$|^[\w.-]*requirements\.txt$", re.I)
PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def manifest_kind(path: Path) -> str | None:
    name = path.name.lower()
    if name in FILENAMES:
        return FILENAMES[name]
    if REQUIREMENTS.match(path.name):
        return "requirements"
    return None


# ====================================================================== version specs
def _version(spec: str) -> tuple[str | None, str, set[str]]:
    """-> (exact version or None, declared version text, flags)
    '==46.0.5' -> ('46.0.5', '46.0.5', set());  '>=42' -> (None, '>=42', {'version-range'});
    ''         -> (None, '', {'version-unpinned'})."""
    spec = spec.split(";")[0].strip().strip('"\'')
    if not spec or spec in ("*", "latest", "x"):
        return None, "", {"version-unpinned"}
    m = re.search(r"(===|==|~=|>=|>|\^|~|=)?\s*v?(\d+(?:\.\d+)*)", spec)
    if not m:
        return None, spec, {"version-unpinned"}
    op = m.group(1) or ""
    exact = op in ("==", "===", "=") or (op == "" and not re.search(r"[<>^~*x]", spec))
    if exact:
        return m.group(2), m.group(2), set()
    return None, spec.replace(" ", ""), {"version-range"}


def _norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ====================================================================== per-format readers
# each yields (ecosystem, name, version spec, line number, evidence)
def _requirements(text: str):
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        egg = re.search(r"#egg=([\w.-]+)", raw)
        if "://" in line:
            if egg:
                yield "pypi", _norm_pypi(egg.group(1)), "", i, raw.strip()
            continue
        m = PEP508.match(line)
        if m:
            yield "pypi", _norm_pypi(m.group(1)), m.group(2), i, raw.strip()


def _line_of(text: str, needle: str) -> int:
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 1


def _pyproject(text: str):
    if tomllib is None:
        return
    data = tomllib.loads(text)
    deps = list(data.get("project", {}).get("dependencies", []))
    for extra in data.get("project", {}).get("optional-dependencies", {}).values():
        deps += extra
    for d in deps:
        m = PEP508.match(d)
        if m:
            yield "pypi", _norm_pypi(m.group(1)), m.group(2), _line_of(text, d), d
    poetry = data.get("tool", {}).get("poetry", {})
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in poetry.get(section, {}).items():
            spec = spec.get("version", "") if isinstance(spec, dict) else str(spec)
            yield "pypi", _norm_pypi(name), spec, _line_of(text, name), f"{name} = {spec}"


def _pipfile(text: str):
    if tomllib is None:
        return
    data = tomllib.loads(text)
    for section in ("packages", "dev-packages"):
        for name, spec in data.get(section, {}).items():
            spec = spec.get("version", "") if isinstance(spec, dict) else str(spec)
            yield "pypi", _norm_pypi(name), spec, _line_of(text, name), f"{name} = {spec}"


def _gomod(text: str):
    in_block = False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//")[0].strip()
        if not line:
            continue
        m = re.match(r"^go\s+(\d+(?:\.\d+)*)$", line)
        if m:
            yield "golang", "stdlib", f"=={m.group(1)}", i, raw.strip()
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-/~]+\.[\w.\-/~]+)\s+(v\S+)$", line)
        if m and (in_block or line.startswith("require")):
            yield "golang", m.group(1), f"=={m.group(2)}", i, raw.strip()


def _npm(text: str):
    data = json.loads(text)
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            yield "npm", name, str(spec), _line_of(text, f'"{name}"'), f'"{name}": "{spec}"'


def _pom(text: str):
    root = ET.fromstring(text)
    strip = lambda tag: tag.rsplit("}", 1)[-1]            # noqa: E731  (namespace-agnostic)
    props = {}
    for el in root.iter():
        if strip(el.tag) == "properties":
            props = {strip(p.tag): (p.text or "").strip() for p in el}
    for el in root.iter():
        if strip(el.tag) != "dependency":
            continue
        kids = {strip(k.tag): (k.text or "").strip() for k in el}
        g, a, v = kids.get("groupId", ""), kids.get("artifactId", ""), kids.get("version", "")
        v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
        if g and a:
            yield "maven", f"{g}:{a}", (f"=={v}" if v and "${" not in v else ""), _line_of(text, f"<artifactId>{a}<"), f"{g}:{a}:{v}"


GRADLE = re.compile(r"""["']([\w.\-]+):([\w.\-]+):([\w.\-+]+)["']""")


def _gradle(text: str):
    for i, raw in enumerate(text.splitlines(), 1):
        for m in GRADLE.finditer(raw):
            yield "maven", f"{m.group(1)}:{m.group(2)}", f"=={m.group(3)}", i, raw.strip()


def _cargo(text: str):
    if tomllib is None:
        return
    data = tomllib.loads(text)
    sections = [data.get("dependencies", {}), data.get("dev-dependencies", {}),
                data.get("workspace", {}).get("dependencies", {})]
    for sec in sections:
        for name, spec in sec.items():
            spec = spec.get("version", "") if isinstance(spec, dict) else str(spec)
            exact = spec.startswith("=")
            yield "cargo", name, (f"=={spec.lstrip('=')}" if exact else f"^{spec}" if spec else ""), \
                _line_of(text, name), f"{name} = {spec}"


READERS = {"requirements": _requirements, "pyproject": _pyproject, "pipfile": _pipfile, "gomod": _gomod,
           "npm": _npm, "pom": _pom, "gradle": _gradle, "cargo": _cargo}


# ====================================================================== entry point
def parse_manifest_files(paths: list[Path], root: Path | None = None, catalog: Catalog | None = None
                         ) -> tuple[list[Finding], list[str]]:
    cat = catalog or load_catalog()
    out, warnings = [], []
    for p in paths:
        kind = manifest_kind(Path(p))
        rel = str(Path(p).relative_to(root)) if root else Path(p).name
        try:
            text = Path(p).read_text(encoding="utf-8", errors="replace")
            entries = list(READERS[kind](text))
        except Exception as e:                         # malformed JSON / XML / TOML: say so, keep scanning
            warnings.append(f"{rel}: could not read {kind} manifest ({type(e).__name__})")
            continue
        seen = set()
        for eco, name, spec, line, evidence in entries:
            hit = cat.library(eco, name)
            if hit is None or (eco, name.lower()) in seen:
                continue
            seen.add((eco, name.lower()))
            version, declared, flags = _version(spec)
            if version and eco == "golang" and name != "stdlib":
                version = declared = f"v{version}"     # Go module versions keep their "v"
            display = hit[1].get("display", name)
            what = "language version (go directive)" if name == "stdlib" else "dependency"
            out.append(Finding(source="code", location=f"{rel}:{line}", asset=rel, algorithm=name,
                               usage=Usage.LIBRARY, flags=flags, evidence=evidence[:160], library=name,
                               purl=make_purl(eco, name, version), version=declared,
                               context=f"{display} declared as {what} in {PurePosixPath(rel).name}"
                                       + (f" ({declared})" if declared else " (version not pinned)")))
    return out, warnings


# ====================================================================== code <-> manifest links
def link_libraries(findings: list[Finding], catalog: Catalog | None = None) -> None:
    """Code findings learn the purl of the library that provides them (nearest manifest above
    the file); library findings learn which files use them."""
    cat = catalog or load_catalog()
    libs = [f for f in findings if f.usage is Usage.LIBRARY]
    if not libs:
        return
    for f in findings:
        if f.source != "code" or f.usage is Usage.LIBRARY or not f.library:
            continue
        best, depth = None, -1
        for lib in libs:
            folder = str(PurePosixPath(lib.asset).parent)
            folder = "" if folder == "." else folder
            if folder and not f.asset.startswith(folder + "/"):
                continue
            if not _provides(lib, f.library, cat):
                continue
            d = len(PurePosixPath(folder).parts) if folder else 0
            if d > depth:
                best, depth = lib, d
        if best is not None:
            f.purl = f.purl or best.purl
            if f.asset not in best.related:
                best.related.append(f.asset)
    for lib in libs:
        lib.related.sort()


def _provides(lib: Finding, module: str, cat: Catalog) -> bool:
    eco = lib.purl.split("/", 1)[0].removeprefix("pkg:")
    hit = cat.library(eco, lib.library)
    imports = hit[1].get("imports", []) if hit else []
    if eco == "golang" and lib.library == "stdlib":
        return "." not in module.split("/", 1)[0]       # crypto/aes, math/rand: no domain = standard library
    imports = [*imports, lib.library]                  # the code scanner may report the package name itself
    return any(module == imp or module.startswith(imp + ".") or module.startswith(imp + "/") for imp in imports)
