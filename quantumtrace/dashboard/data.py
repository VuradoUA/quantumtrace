"""Everything the dashboard shows, as plain Python (no Streamlit here, so it is unit-testable).

Three ways in (decision 10):
    load_folder(path)       the output of `quantumtrace scan --out DIR` (report.json, cbom.json, findings.json)
    scan_to_bundle(path)    scan a file / folder on this machine right now
    save_uploads(files)     files uploaded in the browser (zip archives are unpacked safely), then scan them
"""
from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath

TIER_ORDER = ["SAFE", "MEDIUM", "CRITICAL", "PLAINTEXT", "UNKNOWN", "INFO"]   # stack order (worst in the middle-right)
# Tier = a state, so the reserved STATUS colours (good / warning / critical); PLAINTEXT is not on that scale
# and takes violet; UNKNOWN / INFO are neutral greys. Checked with the dataviz validator: adjacent pairs pass
# CVD + normal-vision floors; MEDIUM yellow is below 3:1 on light, so every mark also carries its text label.
TIER_COLORS = {"SAFE": "#0ca30c", "MEDIUM": "#fab219", "CRITICAL": "#d03b3b", "PLAINTEXT": "#6250d6",
               "UNKNOWN": "#c3c2b7", "INFO": "#898781"}
SOURCE_LABELS = {"pcap": "network", "code": "code", "cloud": "cloud", "config": "config"}
MAX_UPLOAD_BYTES = 200 * 1024 * 1024          # unpacked total
MAX_UPLOAD_FILES = 5000


class DashboardError(Exception):
    """Something the user can fix (wrong folder, bad upload): shown as a message, not a traceback."""


@dataclass
class Bundle:
    report: dict
    cbom: dict | None = None
    findings: list[dict] = field(default_factory=list)
    origin: str = ""                            # "folder report/", "scan of ...", "upload (3 files)"

    @property
    def score(self) -> dict:
        return self.report.get("score", {})


# ====================================================================== inputs
def load_folder(folder: str | Path) -> Bundle:
    folder = Path(folder).expanduser()
    if not (folder / "report.json").is_file():
        raise DashboardError(f"{folder} has no report.json: run `quantumtrace scan <target> --out {folder}` first")
    try:
        report = json.loads((folder / "report.json").read_text())
        cbom = json.loads((folder / "cbom.json").read_text()) if (folder / "cbom.json").is_file() else None
        findings = json.loads((folder / "findings.json").read_text()) if (folder / "findings.json").is_file() else []
    except json.JSONDecodeError as e:
        raise DashboardError(f"{folder}: not valid JSON ({e})") from e
    if "summary" not in report or "roadmap" not in report:
        raise DashboardError(f"{folder}/report.json is not a QuantumTrace report")
    return Bundle(report, cbom, findings, origin=f"report folder {folder}")


def scan_to_bundle(target: str | Path, now: datetime | None = None, label: str | None = None) -> Bundle:
    from ..report import analyse
    from ..scan import scan_path

    target = Path(target).expanduser()
    if not target.exists():
        raise DashboardError(f"{target} does not exist")
    result = scan_path(target, now=now)
    if not result.findings and not any(result.files.values()):
        raise DashboardError(f"nothing QuantumTrace can read in {target} "
                             f"({len(result.skipped)} file(s) skipped)")
    name = label or target.resolve().name or str(target)
    _, bom, report = analyse(result, name, timestamp=now)
    return Bundle(report, bom, [f.to_dict() for f in result.findings], origin=f"scan of {name}")


def save_uploads(files: list[tuple[str, bytes]], dest: Path) -> list[str]:
    """Write uploaded files into `dest`. Zip archives are unpacked, refusing anything that would
    escape `dest` (absolute paths, '..', symlinks) and archives that unpack too big ("zip bombs")."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    total = 0
    for name, data in files:
        safe = _safe_relpath(Path(name).name)
        if safe is None:
            raise DashboardError(f"refused file name {name!r}")
        if safe.lower().endswith(".zip"):
            total += _unzip(data, dest / Path(safe).stem, written, total)
        else:
            total += len(data)
            _check_limits(total, len(written) + 1)
            (dest / safe).write_bytes(data)
            written.append(safe)
    return written


def _safe_relpath(name: str) -> str | None:
    p = PurePosixPath(name.replace("\\", "/"))
    if not name or p.is_absolute() or ".." in p.parts or (p.parts and p.parts[0].endswith(":")):
        return None
    return str(p)


def _check_limits(total: int, count: int) -> None:
    if total > MAX_UPLOAD_BYTES:
        raise DashboardError(f"upload too large (over {MAX_UPLOAD_BYTES // (1024 * 1024)} MB unpacked)")
    if count > MAX_UPLOAD_FILES:
        raise DashboardError(f"upload has too many files (over {MAX_UPLOAD_FILES})")


def _unzip(data: bytes, dest: Path, written: list[str], total: int) -> int:
    import io

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise DashboardError("not a valid zip archive") from e
    added = 0
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:      # symlink entry
                raise DashboardError(f"refused symlink in archive: {info.filename}")
            rel = _safe_relpath(info.filename)
            if rel is None:
                raise DashboardError(f"refused path in archive: {info.filename}")
            added += info.file_size
            _check_limits(total + added, len(written) + 1)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src:
                blob = src.read(MAX_UPLOAD_BYTES + 1)          # never trust file_size in the header
            if len(blob) != info.file_size:
                raise DashboardError(f"archive entry {info.filename} does not match its declared size")
            target.write_bytes(blob)
            written.append(str(PurePosixPath(dest.name) / rel))
    return added


# ====================================================================== tables / numbers for the page
def headline(b: Bundle) -> dict:
    s, summ = b.score, b.report["summary"]
    pqc = (b.report.get("pqc_readiness") or {}).get("network")
    cb = b.report.get("cbom") or {}
    return {
        "score": s.get("quantum_risk_score"),
        "by_source": s.get("by_source", {}),
        "assets": summ["assets"], "findings": summ["findings"],
        "hndl_assets": summ["hndl_assets"], "critical_assets": summ["assets_by_tier"].get("CRITICAL", 0),
        "broken_assets": summ.get("classically_broken_assets", 0),
        "quantum_safe_assets": s.get("assets_quantum_safe", 0), "assets_scored": s.get("assets_scored", 0),
        "pqc_sessions": pqc["pq_sessions"] if pqc else None,
        "tls_sessions": pqc["sessions"].get("tls", 0) if pqc else None,
        "pqc_readiness": pqc["pqc_readiness"] if pqc else None,
        "cbom_valid": cb.get("valid"), "cbom_messages": cb.get("messages", []),
        "files": summ.get("files", {}), "warnings": summ.get("warnings", []),
    }


def tier_rows(b: Bundle) -> list[dict]:
    """Assets per (source, tier), for the stacked bar. Every source x tier present, zeros dropped."""
    rows = []
    for src, info in sorted(b.report["summary"].get("by_source", {}).items()):
        for tier in TIER_ORDER:
            n = info["tiers"].get(tier, 0)
            if n:
                rows.append({"source": SOURCE_LABELS.get(src, src), "tier": tier, "assets": n,
                             "order": TIER_ORDER.index(tier)})
    return rows


def roadmap_rows(b: Bundle, priorities: list[int] | None = None) -> list[dict]:
    out = []
    for r in b.report["roadmap"]:
        if priorities and r["priority"] not in priorities:
            continue
        out.append({"rank": r["rank"], "priority": f"P{r['priority']}", "replace": r["current"],
                    "with": r["replacement"], "standard": r["standard"], "assets": r["asset_count"],
                    "findings": r["finding_count"], "risk": r["risk"], "sources": ", ".join(r["sources"]),
                    "why": r["reason"]})
    return out


def asset_rows(b: Bundle, sources=None, tiers=None, hndl_only=False, text="") -> list[dict]:
    text = text.strip().lower()
    out = []
    for a in b.report["assets"]:
        src = SOURCE_LABELS.get(a["source"], a["source"])
        if sources and src not in sources:
            continue
        if tiers and a["tier"] not in tiers:
            continue
        if hndl_only and not (a["tier"] == "CRITICAL" and a["hndl"]):
            continue
        if text and text not in a["asset"].lower() and text not in (a["worst"] or "").lower():
            continue
        out.append({"asset": a["asset"], "source": src, "verdict": a["label"], "risk": a["risk"],
                    "severity": a["severity"], "exposure": a["exposure"], "why exposed": a["exposure_reason"],
                    "worst": a["worst"], "findings": len(a["findings"]),
                    "flags": ", ".join(f for f in a["flags"] if f not in ("offered", "crypto-library", "prf-hash"))})
    return out


def findings_for_asset(b: Bundle, asset: str) -> list[dict]:
    out = []
    for f in b.findings:
        if f.get("asset") != asset:
            continue
        c = f.get("classification") or {}
        out.append({"id": f["id"], "verdict": c.get("label", ""), "algorithm": f["algorithm"],
                    "usage": f["usage"], "key size": f.get("key_size"), "location": f["location"],
                    "evidence": f.get("evidence", ""), "context": f.get("context", ""),
                    "migrate to": "; ".join(c.get("replacements", [])),
                    "flags": ", ".join(c.get("flags", [])), "confidence": f.get("confidence")})
    return out


def library_rows(b: Bundle) -> list[dict]:
    def status(flags):
        if "pqc-library" in flags:
            return "post-quantum library"
        if "pqc-capable" in flags:
            return "PQC API available"
        if "no-pqc-api" in flags:
            return "no PQC API in this version"
        if "pqc-not-guaranteed" in flags:
            return "depends on the installed version"
        return "classical only / unknown"
    return [{"library": lib["library"], "version": lib["version"] or "(unpinned)", "status": status(lib["flags"]),
             "deprecated": "yes" if "deprecated-library" in lib["flags"] else "",
             "advice": "; ".join(lib["advice"]), "declared in": lib["declared_in"],
             "used by": len(lib["used_by"]), "purl": lib["purl"]} for lib in b.report.get("libraries", [])]


def cbom_rows(b: Bundle) -> list[dict]:
    """What the CBOM contains, by kind of component."""
    if not b.cbom:
        return []
    counts: dict[str, int] = {}
    for c in b.cbom.get("components", []):
        kind = c.get("cryptoProperties", {}).get("assetType") or c["type"]
        counts[kind] = counts.get(kind, 0) + 1
    if b.cbom.get("services"):
        counts["service (endpoint)"] = len(b.cbom["services"])
    names = {"algorithm": "algorithms", "certificate": "certificates", "related-crypto-material": "keys",
             "protocol": "protocol profiles", "library": "libraries", "file": "files"}
    return [{"component": names.get(k, k), "count": v} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]


def downloads(b: Bundle) -> dict[str, str]:
    out = {"report.json": json.dumps(b.report, indent=2)}
    if b.cbom is not None:
        out["cbom.json"] = json.dumps(b.cbom, indent=2)
    if b.findings:
        out["findings.json"] = json.dumps(b.findings, indent=2)
    return out
