"""The JSON audit report and the migration roadmap (decisions 4 and 11).

report.json = what a person (or the dashboard) reads:
    summary      counts per tier / source, HNDL assets, files scanned, warnings
    score        Quantum Risk Score, per-source sub-scores, formula + weights (explainable)
    roadmap      one row per "replace X with Y", priority 1-5, sortable, with the assets it fixes
    assets       every asset with its tier, severity S, exposure E, risk and the finding ids
    libraries    declared crypto libraries and whether they can do PQC
findings.json keeps every single finding (the full evidence); cbom.json is the CycloneDX CBOM.

Roadmap priorities
    1  harvest-now-decrypt-later or no encryption at all   (exposed TODAY)
    2  long-lived keys / certificates, or already broken classically (MD5, SHA-1, RSA < 2048, expired ...)
    3  other Shor-breakable crypto: future forgery
    4  Grover-weakened symmetric crypto / hashes
    5  enablers: library upgrades and deprecated libraries
A row whose every occurrence is only a fallback (`downgrade-risk`) drops one level.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .catalog import Catalog, load_catalog
from .models import Finding, Tier, Usage
from .score import RiskScore

PRIORITY_REASON = {
    1: "exposed today: recordable now, decryptable later (HNDL) or not encrypted",
    2: "long-lived key / certificate, or already broken without a quantum computer",
    3: "Shor-breakable: forgeable once a quantum computer exists",
    4: "Grover-weakened: raise to 256-bit strength",
    5: "enabler: upgrade / replace the library first",
}
URGENT_FLAGS = {"classically-broken", "weak-key-size", "expired", "long-lived", "ca-certificate", "private-key"}


@dataclass
class RoadmapRow:
    priority: int
    current: str
    replacement: str
    standard: str
    tier: str
    hndl: bool
    assets: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)
    risk: float = 0.0
    fallback_only: bool = True
    variants: set[str] = field(default_factory=set)       # RSA: {"1024", "2048"}; AES: {"128-CBC", "128-GCM"}

    def to_dict(self) -> dict:
        current = self.current + (f" ({', '.join(sorted(self.variants))})" if self.variants else "")
        return {"priority": self.priority, "reason": PRIORITY_REASON[self.priority],
                "action": f"{current} -> {self.replacement}", "current": current,
                "replacement": self.replacement, "standard": self.standard, "tier": self.tier, "hndl": self.hndl,
                "assets": sorted(self.assets), "asset_count": len(self.assets), "sources": sorted(self.sources),
                "finding_count": len(self.findings), "risk": round(self.risk, 3)}


def _priority(f: Finding, comp) -> int:
    if comp.tier is Tier.PLAINTEXT or comp.hndl:
        return 1
    # the whole finding counts: RSA inside SHA1withRSA is part of a signature that is forgeable today
    if (comp.flags | f.classification.flags) & URGENT_FLAGS or ("key" in f.details and comp.tier is Tier.CRITICAL):
        return 2
    return 3 if comp.tier is Tier.CRITICAL else 4


def roadmap(score: RiskScore, catalog: Catalog | None = None) -> list[dict]:
    cat = catalog or load_catalog()
    rows: dict[tuple[str, str], RoadmapRow] = {}
    for a in score.assets:
        for f in a.summary.findings:
            c = f.classification
            if c is None:
                continue
            if f.usage is Usage.LIBRARY:
                for r in c.replacements:
                    current, _, repl = r.partition(" -> ")
                    if not repl:                                   # "pycrypto: unmaintained ..." -> replace it
                        current, _, repl = r.partition(": ")
                    row = rows.setdefault((current, repl), RoadmapRow(5, current, repl, "", "INFO", False))
                    _add(row, a, f, fallback=False)
                continue
            if not a.scored:
                continue
            for comp in c.components:
                if comp.tier not in (Tier.CRITICAL, Tier.MEDIUM, Tier.PLAINTEXT) or not comp.replacement:
                    continue
                p = _priority(f, comp)
                base = cat.entry(comp.catalog_key)["name"] if comp.catalog_key else comp.name
                key = (base, comp.replacement)                     # one row per algorithm family + target
                row = rows.setdefault(key, RoadmapRow(p, base, comp.replacement, comp.standard or "",
                                                      comp.tier.value, comp.hndl))
                if comp.name.startswith(base) and comp.name != base:
                    row.variants.add(comp.name[len(base):].strip("- "))
                row.priority = min(row.priority, p)
                row.hndl |= comp.hndl
                _add(row, a, f, fallback="downgrade-risk" in c.flags)
    out = []
    for row in rows.values():
        if row.fallback_only and row.priority < 4:
            row.priority += 1                                      # only a fallback somewhere: less urgent
        out.append(row.to_dict())
    out.sort(key=lambda r: (r["priority"], -r["risk"], -r["asset_count"], r["current"]))
    for i, r in enumerate(out, 1):
        r["rank"] = i
    return out


def _add(row: RoadmapRow, asset, f: Finding, fallback: bool) -> None:
    if asset.asset not in row.assets:
        row.risk += asset.risk
    row.assets.add(asset.asset)
    row.sources.add(asset.source)
    row.findings.add(f.id)
    row.fallback_only &= fallback


def build_report(result, score: RiskScore, target: str, cbom_status: tuple | None = None,
                 timestamp: datetime | None = None) -> dict:
    """`result` is a scan.ScanResult."""
    findings = result.findings
    tiers_assets = Counter(a.tier.value for a in score.assets)
    by_source: dict[str, dict] = {}
    for a in score.assets:
        s = by_source.setdefault(a.source, {"assets": 0, "tiers": Counter(), "hndl_assets": 0})
        s["assets"] += 1
        s["tiers"][a.tier.value] += 1
        s["hndl_assets"] += int(a.tier is Tier.CRITICAL and a.hndl)
    libs = [f for f in findings if f.usage is Usage.LIBRARY]
    report = {
        "tool": {"name": "QuantumTrace", "version": __version__},
        "generated_at": (timestamp or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "summary": {
            "files": {k: len(v) for k, v in result.files.items()}, "files_skipped": len(result.skipped),
            "findings": len(findings), "assets": len(score.assets),
            "assets_by_tier": dict(tiers_assets),
            "findings_by_tier": dict(Counter(f.classification.tier.value for f in findings if f.classification)),
            "hndl_assets": sum(1 for a in score.assets if a.tier is Tier.CRITICAL and a.hndl),
            "classically_broken_assets": sum(1 for a in score.assets if a.summary.flags & {"classically-broken",
                                                                                          "weak-key-size"}),
            "by_source": {k: {**v, "tiers": dict(v["tiers"])} for k, v in sorted(by_source.items())},
            "warnings": list(result.warnings),
        },
        "score": score.to_dict(),
        "pqc_readiness": {"network": result.pcap.to_dict() if result.pcap.files else None},
        "roadmap": roadmap(score),
        "assets": [{"asset": a.asset, "source": a.source, "tier": a.tier.value, "label": a.summary.label,
                    "hndl": a.hndl, "scored": a.scored, "severity": a.severity, "exposure": a.exposure,
                    "exposure_reason": a.reason, "risk": a.risk,
                    "worst": a.worst.algorithm if a.worst else None,
                    "flags": sorted(a.summary.flags), "replacements": a.summary.replacements,
                    "related": sorted({r for f in a.summary.findings for r in f.related}),
                    "findings": [f.id for f in a.summary.findings]} for a in score.assets],
        "libraries": [{"library": f.algorithm, "version": f.version or None, "purl": f.purl, "declared_in": f.location,
                       "flags": sorted(f.classification.flags), "advice": f.classification.replacements,
                       "used_by": sorted(f.related)} for f in libs if f.classification],
    }
    if cbom_status is not None:
        valid, messages = cbom_status
        report["cbom"] = {"format": "CycloneDX", "specVersion": "1.6", "valid": valid, "messages": messages}
    return report


def analyse(result, target: str, timestamp: datetime | None = None, serial: str | None = None,
            validate_cbom: bool = True) -> tuple[RiskScore, dict, dict]:
    """ScanResult -> (score, CycloneDX CBOM, report). Used by the CLI and the dashboard."""
    from .cbom import build_cbom, validate
    from .score import compute

    score = compute(result.findings, result.pcap.pqc_readiness)
    bom = build_cbom(result.findings, score, target=target, timestamp=timestamp, serial=serial)
    status = validate(bom) if validate_cbom else None
    return score, bom, build_report(result, score, target, status, timestamp)
