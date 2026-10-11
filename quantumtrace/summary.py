"""Group per-occurrence findings into per-asset verdicts (used by the CLI now,
the report/CBOM/dashboard later)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, Tier

# flags that describe context rather than a problem; hidden from the one-line summary
QUIET_FLAGS = {"offered", "internet-facing", "hsm-backed", "multi-region", "crypto-library", "prf-hash"}


@dataclass
class AssetSummary:
    source: str
    asset: str
    tier: Tier
    hndl: bool
    findings: list[Finding] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    replacements: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.tier is Tier.CRITICAL:
            return "CRITICAL – HNDL" if self.hndl else "CRITICAL – future"
        return self.tier.value


def summarise(findings: list[Finding]) -> list[AssetSummary]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.source, f.asset or f.location), []).append(f)
    out = []
    for (source, asset), fs in groups.items():
        cls = [f.classification for f in fs if f.classification]
        tier = max((c.tier for c in cls), key=lambda t: t.severity)
        flags = set().union(*(c.flags for c in cls))
        reps: list[str] = []
        for c in cls:
            for r in c.replacements:
                if r not in reps:
                    reps.append(r)
        out.append(AssetSummary(source, asset, tier, any(c.hndl for c in cls), fs, flags, reps))
    out.sort(key=lambda a: (-a.tier.severity, not a.hndl, a.source, a.asset))
    return out
