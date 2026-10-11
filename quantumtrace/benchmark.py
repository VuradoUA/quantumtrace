"""Phase 5: measure QuantumTrace against hand-labelled ground truth.

    quantumtrace benchmark                       # every dataset found, prints the per-source table
    quantumtrace benchmark --out results/        # + benchmark.json and benchmark.md

Datasets (tests/benchmarks/ unless --suite says otherwise):
    holdout          files written and labelled BEFORE QuantumTrace ever ran on them, plus decoys
    adversarial      files written AFTER that run, knowing the parsers, to break them (+ decoys)
    sample-infra     tests/fixtures/sample-infra (configs, certificates, keys, manifests), labelled by reading them
    kit              the organisers' starter kit, labelled in tests/ground_truth.yaml (needs --kit)
    classification   ~85 algorithm names labelled from the challenge definitions, not from catalog.yaml

What is measured, per source (network / code / cloud / config) and per dataset:
    assets      detection precision / recall: a labelled asset must be found; an asset the scanner
                reports that nobody labelled (or a finding in a decoy file) is a false positive
    algorithms  precision / recall / F1 over algorithm FAMILIES (RSA, ECC, AES, SHA-256, HMAC-SHA1,
                ML-KEM-768 ...), so spellings do not matter but a wrong or missing algorithm does
    verdict     tier accuracy (CRITICAL / MEDIUM / SAFE / PLAINTEXT / INFO) with a confusion matrix
    HNDL        precision / recall of the harvest-now-decrypt-later call
    key sizes   share of labelled key sizes reported exactly
    flags       share of labelled facts (expired, weak-key-size, no-forward-secrecy ...) present, and
                labelled "must not be there" facts absent
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .classify import classify_name
from .models import ComponentResult, Finding, Usage
from .summary import summarise

AS_OF = datetime(2026, 10, 11, tzinfo=timezone.utc)   # labels were written on this day (expiry flags depend on it)
SOURCE_NAMES = {"pcap": "network", "code": "code", "cloud": "cloud", "config": "config"}
SOURCES = ["network", "code", "cloud", "config"]
LABELLED = ("holdout", "adversarial", "sample-infra")          # <name>.yaml in the suite folder
TIERS = ["CRITICAL", "MEDIUM", "SAFE", "PLAINTEXT", "UNKNOWN", "INFO", "MISSING"]
# Curves and the algorithms that use them are one family: a label says "P-384", the code says
# ec.ECDSA(...) - both are elliptic-curve crypto broken by Shor. Curve size is checked by tier only.
ECC = {"ECDSA", "ECDH", "EC-P256", "EC-P384", "EC-P521", "EC-SECP256K1", "SM2"}
NOT_A_FAMILY = {"PLAINTEXT"}        # "no crypto" is a verdict, not an algorithm


# ====================================================================== families
def family(comp: ComponentResult) -> str | None:
    if comp.catalog_key is None:
        return "?" + comp.name.lower()                        # unrecognised: never matches a label
    if comp.catalog_key in NOT_A_FAMILY:
        return None
    return "ECC" if comp.catalog_key in ECC else comp.catalog_key


def families_of(name: str, usage: Usage | str = Usage.UNKNOWN, bits: int | None = None,
                mode: str | None = None) -> set[str]:
    """Families of a raw algorithm name, through the same name decomposition the scanner uses
    (so the benchmark measures what the PARSERS find, not how the catalog spells things)."""
    return {f for c in classify_name(str(name), Usage(usage), bits, mode).components if (f := family(c))}


def _one_family(name: str) -> str:
    fams = families_of(name)
    if len(fams) != 1:
        raise ValueError(f"key_sizes entry {name!r} must name exactly one algorithm (got {sorted(fams)})")
    return next(iter(fams))


# ====================================================================== ground truth
@dataclass
class Truth:
    dataset: str
    asset: str
    source: str                          # network / code / cloud / config
    tier: str
    hndl: bool | None                    # None = not decidable from the input
    families: set[str] | None            # None = verdict only (no algorithm list)
    allowed: set[str] = field(default_factory=set)          # may appear, not required (offered fallbacks)
    key_sizes: dict[str, int] = field(default_factory=dict)  # family -> bits
    flags: set[str] = field(default_factory=set)
    absent_flags: set[str] = field(default_factory=set)
    offered: set[str] = field(default_factory=set)          # fallbacks that must be reported as offered


@dataclass
class Setup:
    """A group of identical PCAP sessions (the kit's ground truth labels setups, not hosts)."""
    name: str
    sessions: int
    ports: dict[int, int]
    truth: Truth


@dataclass
class Dataset:
    name: str
    root: Path
    truths: list[Truth]
    decoys: list[str] = field(default_factory=list)
    libraries: set[str] | None = None
    not_libraries: set[str] = field(default_factory=set)
    setups: list[Setup] = field(default_factory=list)


def _label_families(names: list[str], where: str) -> set[str]:
    out: set[str] = set()
    for n in names:
        fams = families_of(n)
        bad = sorted(f for f in fams if f.startswith("?"))
        if bad or not fams:            # a label the catalog cannot read would silently never match
            raise ValueError(f"{where}: label {n!r} is not an algorithm name QuantumTrace knows ({bad})")
        out |= fams
    return out


def load_labelled(path: str | Path) -> Dataset:
    """holdout.yaml / adversarial.yaml / sample-infra.yaml format."""
    path = Path(path)
    doc = yaml.safe_load(path.read_text())
    name = doc["dataset"]
    truths = []
    for a in doc["assets"]:
        algs = a.get("algorithms")
        truths.append(Truth(
            dataset=name, asset=str(a["asset"]), source=a["source"], tier=a["tier"], hndl=a.get("hndl"),
            families=None if algs is None else _label_families(algs, f"{path.name}: {a['asset']}"),
            key_sizes={_one_family(k): int(v) for k, v in (a.get("key_sizes") or {}).items()},
            flags=set(a.get("flags", [])), absent_flags=set(a.get("absent_flags", []))))
    libs = doc.get("libraries")
    return Dataset(name, (path.parent / doc["root"]).resolve(), truths, list(doc.get("decoys", [])),
                   None if libs is None else set(libs), set(doc.get("not_libraries", [])))


def _comp_families(components: list[dict]) -> set[str]:
    out: set[str] = set()
    for c in components or []:
        out |= families_of(c["algorithm"], c.get("usage", "unknown"), c.get("key_size"), c.get("mode"))
    return out


def load_kit(ground_truth: str | Path, kit_root: str | Path) -> Dataset:
    """tests/ground_truth.yaml (verified by hand in Phases 1-3) -> the same Truth rows."""
    gt = yaml.safe_load(Path(ground_truth).read_text())
    truths: list[Truth] = []

    def add(asset, source, item, families):
        exp = item["expected"]
        comps = item.get("components") or []
        flags = set(exp.get("flags", [])) | set(item.get("parser_flags", []))
        flags |= {fl for c in comps for fl in c.get("flags", [])}
        sizes = {}
        for c in comps:
            if c.get("key_size"):
                fams = families_of(c["algorithm"], c.get("usage", "unknown"), c["key_size"], c.get("mode"))
                for f in fams:
                    sizes[f] = int(c["key_size"])
        truths.append(Truth("kit", asset, source, exp["tier"], exp.get("hndl"), families,
                            key_sizes=sizes, flags=flags, absent_flags=set(item.get("absent_flags", []))))

    for item in gt.get("code", []):
        fams = _comp_families(item["components"])
        if "weak-rng" in item.get("parser_flags", []):
            fams.add("INSECURE-RNG")
        add("sample-repos/" + item["file"], "code", item, fams)
    for item in gt.get("cloud_kms", []):
        add(item["alias"], "cloud", item, _comp_families(item["components"]))
    for item in gt.get("cloud_certificates", []):
        add(item["domain"], "cloud", item, _comp_families(item["components"]))
    for item in gt.get("cloud_listeners", []):
        # TLS listeners: the suite list comes from the AWS policy table, checked in test_cloud_parser.py
        add(item["listener"], "cloud", item, _comp_families(item["components"]) if "components" in item else None)

    setups = []
    for item in gt.get("pcap", []):
        exp = item["expected"]
        t = Truth("kit", item["setup"], "network", exp["tier"], exp.get("hndl"), _comp_families(item["components"]),
                  flags=set(exp.get("flags", [])), offered=_comp_families(item.get("also_offered", [])))
        t.allowed = set(t.offered)
        setups.append(Setup(item["setup"], int(item["sessions"]), {int(k): int(v) for k, v in item["ports"].items()}, t))
    libs = {x["library"] for x in gt.get("libraries", [])}
    return Dataset("kit", Path(kit_root).resolve(), truths, libraries=libs, setups=setups)


# ====================================================================== what the scanner said
@dataclass
class Predicted:
    asset: str
    source: str
    tier: str
    hndl: bool
    families: set[str]
    offered: set[str]                    # families seen only as offered (network)
    sizes: set[tuple[str, int]]
    flags: set[str]
    findings: list[Finding]


def predicted_assets(findings: list[Finding]) -> dict[tuple[str, str], Predicted]:
    out = {}
    for a in summarise(findings):
        src = SOURCE_NAMES.get(a.source, a.source)
        fams: set[str] = set()
        offered: set[str] = set()
        sizes: set[tuple[str, int]] = set()
        flags: set[str] = set()
        for f in a.findings:
            flags |= f.flags
            if not f.classification or f.usage is Usage.LIBRARY:
                continue
            flags |= f.classification.flags
            is_offered = src == "network" and "offered" in f.flags | f.classification.flags
            for c in f.classification.components:
                fam = family(c)
                if fam is None:
                    continue
                (offered if is_offered else fams).add(fam)
                if c.bits:
                    sizes.add((fam, c.bits))
        out[(src, a.asset)] = Predicted(a.asset, src, a.tier.value, a.hndl, fams, offered, sizes, flags, a.findings)
    return out


# ====================================================================== scoring one asset
def compare(t: Truth, p: Predicted | None, asset: str | None = None) -> dict:
    row = {"dataset": t.dataset, "source": t.source, "asset": asset or t.asset, "found": p is not None,
           "tier_true": t.tier, "tier_pred": p.tier if p else "MISSING", "hndl_true": t.hndl,
           "hndl_pred": p.hndl if p else False}
    row["tier_ok"] = row["tier_true"] == row["tier_pred"]
    pred = p.families if p else set()
    if t.families is None:
        row["families"] = None
    else:
        row["families"] = {"tp": sorted(pred & t.families), "fn": sorted(t.families - pred),
                           "fp": sorted(pred - t.families - t.allowed)}
    row["key_sizes"] = [{"family": fam, "bits": bits, "ok": bool(p and (fam, bits) in p.sizes)}
                        for fam, bits in sorted(t.key_sizes.items())]
    have = p.flags if p else set()
    row["flags"] = ([{"flag": fl, "expect": True, "ok": fl in have} for fl in sorted(t.flags)]
                    + [{"flag": fl, "expect": False, "ok": fl not in have} for fl in sorted(t.absent_flags)])
    if t.offered:
        seen = (p.offered | p.families) if p else set()
        row["offered"] = {"expected": sorted(t.offered), "missing": sorted(t.offered - seen)}
    return row


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def metrics(rows: list[dict], false_assets: int = 0) -> dict:
    """Aggregate per-asset rows. false_assets = reported assets nobody labelled + decoy hits."""
    found = sum(r["found"] for r in rows)
    hits = [r for r in rows if r["hndl_true"] is not None]
    tp = sum(r["hndl_true"] and r["hndl_pred"] for r in hits)
    fp = sum((not r["hndl_true"]) and r["hndl_pred"] for r in hits)
    fn = sum(r["hndl_true"] and not r["hndl_pred"] for r in hits)
    ftp = sum(len(r["families"]["tp"]) for r in rows if r["families"] is not None)
    ffp = sum(len(r["families"]["fp"]) for r in rows if r["families"] is not None)
    ffn = sum(len(r["families"]["fn"]) for r in rows if r["families"] is not None)
    fprec, frec = _ratio(ftp, ftp + ffp), _ratio(ftp, ftp + ffn)
    sizes = [k for r in rows for k in r["key_sizes"]]
    flags = [k for r in rows for k in r["flags"]]
    confusion: dict[str, dict[str, int]] = defaultdict(Counter)
    for r in rows:
        confusion[r["tier_true"]][r["tier_pred"]] += 1
    return {
        "assets": len(rows),
        "detection": {"found": found, "false_assets": false_assets,
                      "precision": _ratio(found, found + false_assets), "recall": _ratio(found, len(rows))},
        "algorithms": {"tp": ftp, "fp": ffp, "fn": ffn, "precision": fprec, "recall": frec,
                       "f1": round(2 * fprec * frec / (fprec + frec), 4) if fprec and frec else
                       (0.0 if fprec is not None and frec is not None else None)},
        "verdict": {"correct": sum(r["tier_ok"] for r in rows), "accuracy": _ratio(sum(r["tier_ok"] for r in rows),
                                                                                    len(rows)),
                    "confusion": {k: dict(v) for k, v in sorted(confusion.items())}},
        "hndl": {"tp": tp, "fp": fp, "fn": fn, "tn": len(hits) - tp - fp - fn,
                 "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn)},
        "key_sizes": {"ok": sum(k["ok"] for k in sizes), "total": len(sizes),
                      "accuracy": _ratio(sum(k["ok"] for k in sizes), len(sizes))},
        "flags": {"ok": sum(k["ok"] for k in flags), "total": len(flags),
                  "accuracy": _ratio(sum(k["ok"] for k in flags), len(flags))},
    }


# ====================================================================== one dataset
def _jaccard(a: set, b: set) -> float:
    return 1.0 if not a and not b else len(a & b) / len(a | b)


def _in_decoy(asset: str, decoy: str) -> bool:
    return asset == decoy or asset.startswith(decoy + ":") or asset.startswith(decoy + " ")


def evaluate(ds: Dataset, now: datetime = AS_OF) -> dict:
    from .scan import scan_path

    result = scan_path(ds.root, now=now)
    pred = predicted_assets(result.findings)
    rows: list[dict] = []
    used: set[tuple[str, str]] = set()
    for t in ds.truths:
        key = (t.source, t.asset)
        rows.append(compare(t, pred.get(key)))
        used.add(key)

    # PCAP: hosts are matched to the labelled setup whose algorithms they share most; the per-port
    # session counts of every setup must then come out exactly (that catches a wrong match).
    setup_rows = []
    if ds.setups:
        assigned: dict[str, list[str]] = defaultdict(list)
        for key, p in sorted(pred.items()):
            if p.source != "network":
                continue
            scores = [(_jaccard(p.families, s.truth.families), -i) for i, s in enumerate(ds.setups)]
            best = ds.setups[-max(scores)[1]]
            assigned[best.name].append(p.asset)
            rows.append(compare(best.truth, p, asset=p.asset))
            used.add(key)
        for s in ds.setups:
            ports = Counter(int(a.rsplit(":", 1)[1]) for a in assigned[s.name] if a.rsplit(":", 1)[-1].isdigit())
            setup_rows.append({"setup": s.name, "sessions": s.sessions, "assigned": len(assigned[s.name]),
                               "ports_expected": s.ports, "ports_found": dict(sorted(ports.items())),
                               "ok": len(assigned[s.name]) == s.sessions and dict(ports) == s.ports})
            if len(assigned[s.name]) < s.sessions:          # a missing session is a missed asset
                for _ in range(s.sessions - len(assigned[s.name])):
                    rows.append(compare(s.truth, None, asset=f"{s.name} (missing session)"))

    decoys = []
    for d in ds.decoys:
        bad = [p for p in pred.values() if _in_decoy(p.asset, d) and p.tier != "INFO"]
        for p in bad:
            used.add((p.source, p.asset))
        decoys.append({"file": d, "ok": not bad,
                       "false_findings": [f"{f.algorithm} @ {f.location}" for p in bad for f in p.findings]})

    unexpected = [{"asset": p.asset, "source": p.source, "tier": p.tier, "worst": sorted(p.families)}
                  for key, p in sorted(pred.items()) if key not in used and p.tier != "INFO"]
    false_by_source = Counter(u["source"] for u in unexpected)
    for d in ds.decoys:
        for p in pred.values():
            if _in_decoy(p.asset, d) and p.tier != "INFO":
                false_by_source[p.source] += 1

    by_source = {}
    for src in SOURCES:
        sr = [r for r in rows if r["source"] == src]
        if sr or false_by_source.get(src):
            by_source[src] = metrics(sr, false_by_source.get(src, 0))
    out = {"dataset": ds.name, "root": str(ds.root), "files": {k: len(v) for k, v in result.files.items()},
           "all": metrics(rows, sum(false_by_source.values())), "by_source": by_source,
           "rows": rows, "unexpected": unexpected, "decoys": decoys, "pcap_setups": setup_rows}
    if ds.libraries is not None:
        found = {f.algorithm for f in result.findings if f.usage is Usage.LIBRARY}
        tp, fp, fn = found & ds.libraries, found - ds.libraries, ds.libraries - found
        out["libraries"] = {"tp": sorted(tp), "fp": sorted(fp), "fn": sorted(fn),
                            "precision": _ratio(len(tp), len(tp) + len(fp)),
                            "recall": _ratio(len(tp), len(tp) + len(fn)),
                            "not_libraries_reported": sorted(found & ds.not_libraries)}
    return out


# ====================================================================== classification benchmark
def predicted_threat(components: list[ComponentResult]) -> str:
    """The threat follows the public-key part when there is one (it decides the quantum story:
    Shor if classical, none if post-quantum); otherwise Grover if any symmetric part, else none."""
    asym = [c for c in components if c.kind in ("asymmetric", "pqc", "hybrid")]
    if asym:
        return "shor" if any(c.threat == "shor" for c in asym) else "none"
    return "grover" if any(c.threat == "grover" for c in components) else "none"


def evaluate_classification(path: str | Path) -> dict:
    cases = yaml.safe_load(Path(path).read_text())["cases"]
    rows = []
    for case in cases:
        c = classify_name(case["name"], Usage(case.get("usage", "unknown")), case.get("bits"))
        got = {"tier": c.tier.value, "threat": predicted_threat(c.components), "hndl": c.hndl}
        want = {"tier": case["tier"], "threat": case["threat"], "hndl": bool(case.get("hndl", False))}
        rows.append({"name": case["name"], "usage": case.get("usage"), "bits": case.get("bits"),
                     "want": want, "got": got, "ok": {k: got[k] == want[k] for k in want}})
    n = len(rows)
    acc = {k: _ratio(sum(r["ok"][k] for r in rows), n) for k in ("tier", "threat", "hndl")}
    return {"cases": n, "accuracy": acc, "all_correct": sum(all(r["ok"].values()) for r in rows),
            "misses": [r for r in rows if not all(r["ok"].values())]}


# ====================================================================== everything
def run(suite: str | Path, kit: str | Path | None = None, only: list[str] | None = None,
        now: datetime = AS_OF) -> dict:
    suite = Path(suite)
    out: dict = {"as_of": now.strftime("%Y-%m-%d"), "datasets": {}, "skipped": {}}
    want = lambda n: not only or n in only          # noqa: E731
    for name in LABELLED:
        if want(name):
            out["datasets"][name] = evaluate(load_labelled(suite / f"{name}.yaml"), now)
    if want("kit"):
        gt = suite.parent / "ground_truth.yaml"
        if kit and (Path(kit) / "network-capture").is_dir() and gt.is_file():
            out["datasets"]["kit"] = evaluate(load_kit(gt, kit), now)
        else:
            out["skipped"]["kit"] = f"starter kit not found at {kit}" if kit else "no --kit given"
    if want("classification"):
        out["classification"] = evaluate_classification(suite / "classification.yaml")
    base = suite.resolve().parents[1]                  # the repository: keep paths in the output portable
    for d in out["datasets"].values():
        d["root"] = os.path.relpath(d["root"], base)
    rows = [r for d in out["datasets"].values() for r in d["rows"]]
    false = Counter()
    for d in out["datasets"].values():
        for src, m in d["by_source"].items():
            false[src] += m["detection"]["false_assets"]
    out["by_source"] = {src: metrics([r for r in rows if r["source"] == src], false[src])
                        for src in SOURCES if any(r["source"] == src for r in rows) or false[src]}
    out["all"] = metrics(rows, sum(false.values()))
    return out


# ====================================================================== text output
def _pct(x) -> str:
    return "–" if x is None else f"{100 * x:.0f}%"


def table(by_source: dict, overall: dict | None = None) -> list[str]:
    lines = ["| source | assets | detection P / R | algorithms P / R (F1) | verdict acc. | HNDL P / R | key sizes |",
             "|---|---:|---|---|---:|---|---:|"]
    items = list(by_source.items()) + ([("**all**", overall)] if overall else [])
    for src, m in items:
        a, h, k = m["algorithms"], m["hndl"], m["key_sizes"]
        lines.append(f"| {src} | {m['assets']} | {_pct(m['detection']['precision'])} / {_pct(m['detection']['recall'])}"
                     f" | {_pct(a['precision'])} / {_pct(a['recall'])} ({_pct(a['f1'])})"
                     f" | {_pct(m['verdict']['accuracy'])} | {_pct(h['precision'])} / {_pct(h['recall'])}"
                     f" | {k['ok']}/{k['total']} |")
    return lines


def problems(d: dict) -> list[str]:
    out = []
    for r in d["rows"]:
        why = []
        if not r["found"]:
            why.append("not found")
        elif not r["tier_ok"]:
            why.append(f"verdict {r['tier_pred']} (label {r['tier_true']})")
        if r["hndl_true"] is not None and r["found"] and r["hndl_true"] != r["hndl_pred"]:
            why.append(f"HNDL {r['hndl_pred']} (label {r['hndl_true']})")
        if r["families"] and r["found"]:
            if r["families"]["fn"]:
                why.append("missed " + ", ".join(r["families"]["fn"]))
            if r["families"]["fp"]:
                why.append("extra " + ", ".join(r["families"]["fp"]))
        why += [f"key size {k['family']}-{k['bits']} not reported" for k in r["key_sizes"] if not k["ok"]]
        why += [("missing flag " if k["expect"] else "unwanted flag ") + k["flag"] for k in r["flags"] if not k["ok"]]
        if r.get("offered", {}).get("missing"):
            why.append("offered fallback not reported: " + ", ".join(r["offered"]["missing"]))
        if why:
            out.append(f"- `{r['asset']}` ({r['source']}): " + "; ".join(why))
    out += [f"- unexpected asset `{u['asset']}` ({u['source']}, {u['tier']})" for u in d["unexpected"]]
    out += [f"- decoy `{x['file']}`: " + "; ".join(x["false_findings"]) for x in d["decoys"] if not x["ok"]]
    out += [f"- PCAP setup `{s['setup']}`: {s['assigned']} hosts (labelled {s['sessions']}), ports {s['ports_found']}"
            for s in d["pcap_setups"] if not s["ok"]]
    lib = d.get("libraries")
    if lib and (lib["fp"] or lib["fn"]):
        out.append(f"- libraries: missed {lib['fn'] or 'none'}, extra {lib['fp'] or 'none'}")
    return out


def markdown(res: dict) -> str:
    lines = [f"# QuantumTrace benchmark ({res['as_of']})", "", "## All datasets, per source", ""]
    lines += table(res["by_source"], res["all"])
    for name, d in res["datasets"].items():
        lines += ["", f"## {name}", "", f"Scanned `{d['root']}`: {d['files']}", ""]
        lines += table(d["by_source"], d["all"])
        if d["decoys"]:
            lines += ["", f"Decoys clean: {sum(x['ok'] for x in d['decoys'])} / {len(d['decoys'])}"]
        if d.get("libraries"):
            lib = d["libraries"]
            lines += ["", f"Libraries: precision {_pct(lib['precision'])}, recall {_pct(lib['recall'])}"]
        if d["pcap_setups"]:
            lines += ["", "PCAP setups: " + ", ".join(f"{s['setup']} {s['assigned']}/{s['sessions']}"
                                                       f"{'' if s['ok'] else ' ✗'}" for s in d["pcap_setups"])]
        p = problems(d)
        lines += ["", "Differences from the labels:" if p else "No differences from the labels.", *p]
    for name, why in res.get("skipped", {}).items():
        lines += ["", f"## {name}: skipped ({why})"]
    c = res.get("classification")
    if c:
        lines += ["", "## Classification (algorithm names, labelled independently of the catalog)", "",
                  f"{c['cases']} cases: tier {_pct(c['accuracy']['tier'])}, threat {_pct(c['accuracy']['threat'])}, "
                  f"HNDL {_pct(c['accuracy']['hndl'])}"]
        lines += [f"- `{m['name']}` ({m['usage']}{', ' + str(m['bits']) if m['bits'] else ''}): got {m['got']}, "
                  f"label {m['want']}" for m in c["misses"]]
    return "\n".join(lines) + "\n"


def write(res: dict, out_dir: str | Path) -> list[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    j, m = out_dir / "benchmark.json", out_dir / "benchmark.md"
    j.write_text(json.dumps(res, indent=2, sort_keys=False, default=sorted))
    m.write_text(markdown(res))
    return [j, m]
