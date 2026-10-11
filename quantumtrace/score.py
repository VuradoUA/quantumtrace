"""The Quantum Risk Score (decision 4): one explainable number, 0 = nothing to fix, 100 = everything exposed.

Per ASSET (a file, a host:port, a KMS key, a certificate ...), because that is what gets fixed:

    severity  S = worst finding of the asset:  CRITICAL 1.0 | PLAINTEXT 1.0 | MEDIUM 0.4 | SAFE 0.0
                  a finding that is only a fallback (`downgrade-risk`) counts half
                  + 0.3 if that worst problem is ALSO broken today (classically-broken / weak-key-size), max 1.0
    exposure  E = 1.5  data can be recorded now and decrypted later (HNDL) or is not encrypted at all
                  1.3  long-lived trust: certificates, KMS / key files, CA or >= 5-year material
                  1.0  everything else (e.g. a signature in code, a hash)

    source score     = 100 * sum(E * S) / sum(E)          over the scored assets of that source
    Quantum Risk Score = mean of the source scores        (network, code, cloud, config weigh the same,
                                                           so 135 PCAP sessions cannot drown 24 code files)

Scored assets: worst tier CRITICAL / MEDIUM / SAFE / PLAINTEXT. INFO (libraries, HTTP->HTTPS redirects)
and UNKNOWN-only assets are listed but not scored.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, Tier, Usage
from .summary import AssetSummary, summarise

SEVERITY = {Tier.CRITICAL: 1.0, Tier.PLAINTEXT: 1.0, Tier.MEDIUM: 0.4, Tier.SAFE: 0.0}
BROKEN_BONUS = 0.3
FALLBACK_FACTOR = 0.5
EXPOSURE_HNDL, EXPOSURE_LONG_LIVED, EXPOSURE_DEFAULT = 1.5, 1.3, 1.0
BROKEN_FLAGS = {"classically-broken", "weak-key-size"}
LONG_LIVED_FLAGS = {"long-lived", "ca-certificate", "private-key"}
SOURCE_NAMES = {"pcap": "network", "code": "code", "cloud": "cloud", "config": "config"}

FORMULA = ("asset risk = S x E; S = worst finding (CRITICAL/PLAINTEXT 1.0, MEDIUM 0.4, SAFE 0; fallback-only "
           "x0.5; +0.3 if also classically broken, max 1); E = 1.5 HNDL or plaintext, 1.3 long-lived keys/certs, "
           "1.0 otherwise; source score = 100 x sum(S x E) / sum(E); Quantum Risk Score = mean of source scores")


@dataclass
class AssetRisk:
    source: str
    asset: str
    tier: Tier
    hndl: bool
    severity: float               # S
    exposure: float               # E
    reason: str                   # why this exposure
    worst: Finding | None         # the finding that set S
    summary: AssetSummary = field(repr=False, default=None)

    @property
    def risk(self) -> float:
        return round(self.severity * self.exposure, 4)

    @property
    def scored(self) -> bool:
        return self.tier in SEVERITY


@dataclass
class RiskScore:
    score: float | None                          # headline 0-100 (None: nothing scorable)
    by_source: dict[str, float]                  # "network" / "code" / "cloud" / "config" -> 0-100
    pooled: float | None                         # all assets in one pool (for comparison)
    assets: list[AssetRisk]
    pqc_readiness: float | None = None           # share of TLS sessions with a PQ group (PCAP)

    def to_dict(self) -> dict:
        scored = [a for a in self.assets if a.scored]
        return {
            "quantum_risk_score": self.score, "by_source": self.by_source, "pooled_score": self.pooled,
            "pqc_readiness_network": round(self.pqc_readiness, 4) if self.pqc_readiness is not None else None,
            "assets_scored": len(scored), "assets_not_scored": len(self.assets) - len(scored),
            "assets_quantum_safe": sum(1 for a in scored if a.severity == 0),
            "formula": FORMULA,
            "weights": {"severity": {t.value: w for t, w in SEVERITY.items()}, "broken_bonus": BROKEN_BONUS,
                        "fallback_factor": FALLBACK_FACTOR,
                        "exposure": {"hndl_or_plaintext": EXPOSURE_HNDL, "long_lived": EXPOSURE_LONG_LIVED,
                                     "default": EXPOSURE_DEFAULT}},
        }


# ====================================================================== per finding / per asset
def finding_severity(f: Finding) -> float:
    c = f.classification
    if c is None or c.tier not in SEVERITY:
        return 0.0
    s = SEVERITY[c.tier]
    if "downgrade-risk" in c.flags:
        s *= FALLBACK_FACTOR
    if s and c.flags & BROKEN_FLAGS:
        s = min(1.0, s + BROKEN_BONUS)
    return round(s, 4)


def exposure(findings: list[Finding]) -> tuple[float, str]:
    cls = [f.classification for f in findings if f.classification]
    if any(c.hndl for c in cls) or any(c.tier is Tier.PLAINTEXT for c in cls):
        return EXPOSURE_HNDL, "harvest-now-decrypt-later" if any(c.hndl for c in cls) else "not encrypted"
    if any(f.usage is Usage.CERTIFICATE or "key" in f.details or f.flags & LONG_LIVED_FLAGS for f in findings):
        return EXPOSURE_LONG_LIVED, "long-lived key or certificate"
    return EXPOSURE_DEFAULT, "default"


def asset_risks(findings: list[Finding]) -> list[AssetRisk]:
    out = []
    for a in summarise(findings):
        worst = max(a.findings, key=finding_severity, default=None)
        s = finding_severity(worst) if worst else 0.0
        e, why = exposure(a.findings)
        out.append(AssetRisk(a.source, a.asset, a.tier, a.hndl, s, e, why, worst, a))
    out.sort(key=lambda r: (-r.risk, -r.tier.severity, r.source, r.asset))
    return out


def _pool(risks: list[AssetRisk]) -> float | None:
    scored = [r for r in risks if r.scored]
    total = sum(r.exposure for r in scored)
    return round(100 * sum(r.severity * r.exposure for r in scored) / total, 1) if total else None


def compute(findings: list[Finding], pqc_readiness: float | None = None) -> RiskScore:
    risks = asset_risks(findings)
    by_source = {}
    for src, label in SOURCE_NAMES.items():
        s = _pool([r for r in risks if r.source == src])
        if s is not None:
            by_source[label] = s
    headline = round(sum(by_source.values()) / len(by_source), 1) if by_source else None
    return RiskScore(score=headline, by_source=by_source, pooled=_pool(risks), assets=risks,
                     pqc_readiness=pqc_readiness)
