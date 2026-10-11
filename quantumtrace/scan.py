"""The scan pipeline: find inputs -> run the right parser -> link -> classify every finding.

    quantumtrace scan <file or folder>

Input types are auto-detected (decision 5):
    cloud     *.json (not package.json)            AWS KMS / ELB / ACM exports, generic JSON
    code      *.py *.java *.go (+ regex fallback)  source code
    manifest  requirements.txt, go.mod, package.json, pom.xml, Cargo.toml, ...   crypto libraries
    cert      *.pem *.crt *.der *.key *.pub *.p12, authorized_keys, known_hosts, id_*   certificates & keys
    config    nginx / Apache / OpenSSH configs     by name, else by content (".conf", no extension)
    pcap      *.pcap *.pcapng *.cap                network traffic (tshark)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .catalog import load_catalog
from .classify import classify
from .models import Finding
from .parsers import certs, config, manifests
from .parsers.cloud import parse_cloud_files
from .parsers.code import EXTENSIONS as CODE_EXTENSIONS
from .parsers.code import parse_code_files
from .parsers.pcap import EXTENSIONS as PCAP_EXTENSIONS
from .parsers.pcap import PcapStats, parse_pcap_files

SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", ".pytest_cache", "site-packages",
             "report", "build", "dist"}
KINDS = {".json": "cloud", **{ext: "code" for ext in CODE_EXTENSIONS}, **{ext: "pcap" for ext in PCAP_EXTENSIONS}}
ORDER = ["cloud", "code", "manifest", "cert", "config", "pcap"]


@dataclass
class ScanResult:
    findings: list[Finding]
    files: dict[str, list[str]] = field(default_factory=dict)    # kind -> files scanned
    skipped: list[str] = field(default_factory=list)             # files with no parser
    pcap: PcapStats = field(default_factory=PcapStats)           # session counts, offered groups, PQC readiness
    warnings: list[str] = field(default_factory=list)            # e.g. tshark missing


def detect_kind(p: Path) -> str | None:
    if manifests.manifest_kind(p):                     # before ".json": package.json is not a cloud export
        return "manifest"
    if certs.is_cert_file(p):
        return "cert"
    kind = KINDS.get(p.suffix.lower())
    if kind:
        return kind
    if config.detect(p):
        return "config"
    return None


def collect(target: Path) -> tuple[dict[str, list[Path]], list[Path]]:
    target = Path(target)
    paths = [target] if target.is_file() else [
        p for p in sorted(target.rglob("*"))
        if p.is_file() and not any(part in SKIP_DIRS or part.endswith(".egg-info") for part in p.parts)]
    by_kind: dict[str, list[Path]] = {}
    skipped = []
    for p in paths:
        kind = detect_kind(p)
        if kind:
            by_kind.setdefault(kind, []).append(p)
        else:
            skipped.append(p)
    return by_kind, skipped


def scan_path(target: str | Path, now: datetime | None = None) -> ScanResult:
    target = Path(target)
    root = target if target.is_dir() else target.parent
    cat = load_catalog()
    now = now or datetime.now(timezone.utc)
    by_kind, skipped = collect(target)
    rel = lambda p: str(p.relative_to(root))          # noqa: E731
    known = [rel(p) for ps in by_kind.values() for p in ps]

    findings: list[Finding] = []
    warnings: list[str] = []
    if "cloud" in by_kind:
        findings += parse_cloud_files(by_kind["cloud"], root=root, now=now, catalog=cat)
    if "code" in by_kind:
        findings += parse_code_files(by_kind["code"], root=root, catalog=cat)
    if "manifest" in by_kind:
        found, w = manifests.parse_manifest_files(by_kind["manifest"], root=root, catalog=cat)
        findings += found
        warnings += w
    cert_findings = certs.parse_cert_files(by_kind.get("cert", []), root=root, now=now, catalog=cat)
    findings += cert_findings
    if "config" in by_kind:
        findings += config.parse_config_files(by_kind["config"], root=root, catalog=cat,
                                              cert_families=certs.key_families(cert_findings), known_files=known)
    for kind, source in (("code", "code"), ("config", "config")):  # PEM blocks pasted into code / configs
        for p in by_kind.get(kind, []):
            text = _text_with_pem(p)
            if text:
                findings += certs.parse_pem_text(text, rel(p), cat, now, source=source, embedded=True)

    pstats = PcapStats()
    if "pcap" in by_kind:
        pfindings, pstats, w = parse_pcap_files(by_kind["pcap"], root=root, now=now, catalog=cat)
        findings += pfindings
        warnings += w

    for i, f in enumerate(findings, 1):               # stable ids per scan (same input -> same ids)
        f.id = f"f-{i:04d}"
    manifests.link_libraries(findings, cat)
    _link_back(findings)
    for f in findings:
        classify(f, catalog=cat)
    return ScanResult(findings=findings,
                      files={k: [rel(p) for p in by_kind[k]] for k in ORDER if k in by_kind},
                      skipped=[rel(p) for p in skipped], pcap=pstats, warnings=warnings)


def _text_with_pem(p: Path) -> str | None:
    try:
        raw = p.read_bytes()
    except OSError:
        return None
    return raw.decode("utf-8", "replace") if b"-----BEGIN " in raw else None


def _link_back(findings: list[Finding]) -> None:
    """If A says it is related to asset B (a TLS server -> its certificate file, a manifest ->
    the code that uses the library), B's findings also point back to A."""
    by_asset: dict[str, list[Finding]] = {}
    for f in findings:
        by_asset.setdefault(f.asset, []).append(f)
    for f in findings:
        for other in list(f.related):
            for g in by_asset.get(other, []):
                if g is not f and f.asset != g.asset and f.asset not in g.related:
                    g.related.append(f.asset)
